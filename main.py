from __future__ import annotations
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
import os
import firebase_admin
import json
from firebase_admin import credentials, auth, firestore
import requests
import uvicorn


from typing import List, Optional
import pydanticmodels

# --- Environment and Firebase Initialization ---
load_dotenv()

try:
    # Check for the environment variable first
    firebase_creds_json = os.getenv("FIREBASE_CREDS_JSON")
    if firebase_creds_json:
        print("Initializing Firebase from environment variable...")
        cred_dict = json.loads(firebase_creds_json)
        cred = credentials.Certificate(cred_dict)
    else:
        # Fallback to the local file path for development
        print("Initializing Firebase from file path...")
        cred_path = os.getenv("FIREBASE_ADMIN_SDK_PATH", "xplore-84cb1-firebase-adminsdk-fbsvc-b772c2bc75.json")
        cred = credentials.Certificate(cred_path)

    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {e}")
    exit()


# --- FastAPI App Instance ---
app = FastAPI(
    title="Firebase Auth & Events API",
    description="An API for user management and event handling using FastAPI and Firebase.",
    version="1.0.1", # Updated version
)





# --- Firebase Configuration ---
FIREBASE_WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY")
if not FIREBASE_WEB_API_KEY:
    print("FATAL: FIREBASE_WEB_API_KEY environment variable not set.")
    exit()
FIREBASE_SIGN_IN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"

# --- Authentication Dependency ---
bearer_scheme = HTTPBearer()

def get_current_user(token: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    """
    Dependency function to verify Firebase ID token and get user data.
    Raises HTTPException 401 if the token is invalid.
    """
    try:
        decoded_token = auth.verify_id_token(token.credentials)
        return decoded_token
    except Exception as e:
        print(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# --- Authentication Endpoints ---

@app.post("/signup", status_code=status.HTTP_201_CREATED)
def sign_up(user_data: pydanticmodels.UserSignup):
    """
    Handles new user registration and creates a corresponding user document in Firestore.
    """
    try:
        # Step 1: Create the user in Firebase Authentication
        user = auth.create_user(
            email=user_data.email,
            password=user_data.password,
            display_name=user_data.name
        )
        print(f"Successfully created new auth user: {user.uid}")

        # Step 2: Create a user document in Firestore with all required fields
        # UPDATED: Added new fields from UserProfile models to prevent data inconsistency
        user_doc_ref = db.collection('users').document(user.uid)
        user_doc_ref.set({
            'uid': user.uid,
            'email': user.email,
            'name': user_data.name,
            'role': 'user',  # Default role
            'createdAt': firestore.SERVER_TIMESTAMP,
            # Initialize other profile fields
            'rollno': None,
            'branch': None,
            'hostelName': None,
            'roomNo': None,
            'skills': None,
        })
        print(f"Successfully created Firestore document for user: {user.uid}")

        return {"message": "User created successfully", "uid": user.uid}

    except auth.EmailAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"The email '{user_data.email}' is already registered."
        )
    except Exception as e:
        print(f"An unexpected error occurred during signup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred during signup."
        )


@app.post("/login")
def login_with_email_password(user_data: pydanticmodels.UserPasswordLogin):
    """
    Handles user sign-in using email and password via the Firebase REST API.
    """
    payload = {
        "email": user_data.email,
        "password": user_data.password,
        "returnSecureToken": True
    }
    try:
        response = requests.post(FIREBASE_SIGN_IN_URL, json=payload)
        response.raise_for_status()
        data = response.json()
        return {
            "message": "User logged in successfully",
            "idToken": data.get("idToken"),
            "refreshToken": data.get("refreshToken"),
            "uid": data.get("localId")
        }
    except requests.exceptions.HTTPError as err:
        error_json = err.response.json().get("error", {})
        error_message = error_json.get("message", "Invalid credentials.")
        if "INVALID_PASSWORD" in error_message or "EMAIL_NOT_FOUND" in error_message:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An internal server error occurred: {e}"
        )

# --- Event Management Endpoints (Protected) ---

@app.post("/events", status_code=status.HTTP_201_CREATED, response_model=pydanticmodels.EventResponse)
def create_event(event_data: pydanticmodels.Event, current_user: dict = Depends(get_current_user)):
    """
    Creates a new event. This endpoint is protected and requires authentication.
    Only users with the 'admin' role can create events.
    """
    try:
        # Role-Based Access Control (RBAC)
        uid = current_user['uid']
        user_doc = db.collection('users').document(uid).get()
        
        if not user_doc.exists or user_doc.to_dict().get('role') != 'admin':
            # This HTTPException will now be caught and handled correctly.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to create events."
            )

        # Prepare the data for Firestore
        event_to_save = event_data.model_dump()
        event_to_save['participants'] = []
        event_to_save['createdAt'] = firestore.SERVER_TIMESTAMP
        
        # Convert date object to string for Firestore compatibility
        if 'event_date' in event_to_save:
            event_to_save['event_date'] = event_to_save['event_date'].isoformat()

        # Create the document in Firestore
        event_ref = db.collection('events').document()
        event_ref.set(event_to_save)
        
        # Prepare the response data
        response_data = event_data.model_dump()
        response_data['id'] = event_ref.id
        response_data['participants'] = []
        
        print(f"Admin user {uid} successfully created event with ID: {event_ref.id}")
        return response_data

    # FIX: Catch HTTPException specifically and re-raise it.
    # This ensures that intentional HTTP errors (like 403, 404) are sent to the client
    # instead of being masked as a 500 Internal Server Error.
    except HTTPException as he:
        raise he
    
    # This block will now only catch truly unexpected errors.
    except Exception as e:
        print(f"An unexpected error occurred while creating an event: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while creating the event."
        )
@app.get("/events", response_model=List[pydanticmodels.EventResponse])
def get_all_events(current_user: dict = Depends(get_current_user)):
    """
    Retrieves all events. Any authenticated user can view events.
    """
    try:
        events_ref = db.collection('events').stream()
        events_list = []
        for event in events_ref:
            event_data = event.to_dict()
            event_data['id'] = event.id
            events_list.append(event_data)
        
        print(f"User {current_user['uid']} successfully fetched {len(events_list)} events.")
        return events_list
        
    except Exception as e:
        print(f"An unexpected error occurred while fetching events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while fetching events."
        )

# --- Event Participation Endpoints ---

@app.post("/events/{event_id}/participate", status_code=status.HTTP_200_OK)
def participate_in_event(event_id: str, current_user: dict = Depends(get_current_user)):
    """
    Allows the current authenticated user to participate in an event.
    """
    try:
        uid = current_user['uid']
        event_ref = db.collection('events').document(event_id)
        
        event_ref.update({
            'participants': firestore.ArrayUnion([uid])
        })
        
        return {"message": f"Successfully registered for event {event_id}"}
    except Exception as e:
        print(f"Error during event participation: {e}")
        raise HTTPException(status_code=500, detail="Could not participate in event.")

@app.post("/events/{event_id}/leave", status_code=status.HTTP_200_OK)
def leave_event(event_id: str, current_user: dict = Depends(get_current_user)):
    """
    Allows the current authenticated user to leave an event they are participating in.
    """
    try:
        uid = current_user['uid']
        event_ref = db.collection('events').document(event_id)
        
        event_ref.update({
            'participants': firestore.ArrayRemove([uid])
        })
        
        return {"message": f"Successfully left event {event_id}"}
    except Exception as e:
        print(f"Error while leaving event: {e}")
        raise HTTPException(status_code=500, detail="Could not leave event.")

# --- User Profile Endpoints ---

@app.get("/users/me", response_model=pydanticmodels.UserProfilePrivate)
def get_own_profile(current_user: dict = Depends(get_current_user)):
    """
    Fetches the profile of the currently authenticated user.
    """
    try:
        uid = current_user['uid']
        user_doc = db.collection('users').document(uid).get()
        if user_doc.exists:
            return user_doc.to_dict()
        raise HTTPException(status_code=404, detail="User profile not found.")
    except Exception as e:
        print(f"Error fetching own profile: {e}")
        raise HTTPException(status_code=500, detail="Could not fetch user profile.")

# NEW ENDPOINT: To edit the current user's profile
@app.put("/users/me", response_model=pydanticmodels.UserProfilePrivate)
def update_own_profile(
    profile_data:pydanticmodels.UserProfileUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Updates the profile of the currently authenticated user.
    The user can send only the fields they want to update.
    """
    uid = current_user['uid']
    user_ref = db.collection('users').document(uid)
    
    # Use exclude_unset=True to only get the fields that were actually sent in the request
    update_data = profile_data.model_dump(exclude_unset=True)
    
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No update data provided."
        )
        
    try:
        # Update the user document in Firestore
        user_ref.update(update_data)
        
        # Also update the display_name in Firebase Auth if 'name' is being changed
        if 'name' in update_data:
            auth.update_user(uid, display_name=update_data['name'])
            
        # Fetch the updated document to return the full, updated profile
        updated_doc = user_ref.get()
        if not updated_doc.exists:
            # This is an edge case, but good to handle
            raise HTTPException(status_code=404, detail="User profile not found after update.")
            
        print(f"User {uid} successfully updated their profile with data: {update_data}")
        return updated_doc.to_dict()
        
    except Exception as e:
        print(f"Error updating profile for user {uid}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while updating the profile."
        )


@app.get("/users/{user_id}", response_model=pydanticmodels.UserProfilePublic)
def get_user_profile(user_id: str, current_user: dict = Depends(get_current_user)):
    """
    Fetches the public profile of a specific user by their UID.
    """
    try:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            return user_doc.to_dict()
        raise HTTPException(status_code=404, detail="User profile not found.")
    except Exception as e:
        print(f"Error fetching user profile for {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Could not fetch user profile.")


# --- Root Endpoint ---

@app.get("/")
def read_root():
    return {"message": "Welcome to the FastAPI Firebase API for Events and Users."}

# To run this application:
# 1. Make sure you have a .env file with your FIREBASE_WEB_API_KEY and FIREBASE_ADMIN_SDK_PATH.
# 2. Run the command in your terminal: uvicorn your_filename:app --reload

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)