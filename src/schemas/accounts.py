from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database.validators.accounts import validate_email, validate_password_strength


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    def validate_email(cls, value):
        return validate_email(value)


class UserCreate(UserBase):
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password_strength(value)


class UserRead(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivate(UserBase):
    token: str


class PasswordReset(UserBase):
    token: str
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password_strength(value)


class UserLogin(UserCreate):
    pass


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    type: str = "bearer"


class UpdateAccessToken(BaseModel):
    refresh_token: str


class NewAccessToken(BaseModel):
    access_token: str
