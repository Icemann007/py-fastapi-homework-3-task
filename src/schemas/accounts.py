from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database.validators import accounts
from database.validators.accounts import validate_password_strength


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    def validate_email(cls, value):
        return accounts.validate_email(value)


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBase):
    token: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        return validate_password_strength(value)


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
