from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import date
class UserSignup(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=6, description="User's password (min 6 characters)")
    name: str = Field(..., description="User's full name")

class UserPasswordLogin(BaseModel):
    email: EmailStr
    password: str

class Event(BaseModel):
    name: str = Field(..., description="The name of the event")
    event_date: date = Field(..., description="The date of the event in YYYY-MM-DD format")
    description: str = Field(..., description="A detailed description of the event")

class EventResponse(Event):
    id: str = Field(..., description="The unique ID of the event document")
    participants: List[str] = Field([], description="List of user UIDs participating in the event")

class UserProfilePublic(BaseModel):
    uid: str
    name: str
    email: EmailStr # CORRECTED: Removed incorrect Field description
    rollno: Optional[int] = None
    branch: Optional[str] = None
    hostelName: Optional[str] = None
    roomNo: Optional[str] = None
    skills: Optional[str] = None

class UserProfilePrivate(UserProfilePublic):
    role: str

# NEW MODEL: For updating user profile. All fields are optional.
class UserProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, description="User's full name")
    rollno: Optional[int] = Field(None, description="User's roll number")
    branch: Optional[str] = Field(None, description="User's branch of study")
    hostelName: Optional[str] = Field(None, description="User's hostel name")
    roomNo: Optional[str] = Field(None, description="User's room number")
    skills: Optional[str] = Field(None, description="A summary of the user's skills")
