from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRead,
    UserCreate,
    UserActivate,
    UserBase,
    PasswordReset,
    UserLogin,
    LoginResponse,
    NewAccessToken,
    UpdateAccessToken,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post("/register/", response_model=UserRead, status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user_email = result.scalar_one_or_none()
    if db_user_email:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")

    role = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    db_role = role.scalar_one()

    try:
        hashed_password = hash_password(user.password)
        db_user = UserModel(email=user.email, _hashed_password=hashed_password, group_id=db_role.id)
        db.add(db_user)
        await db.flush()

        user_token = ActivationTokenModel(user=db_user)
        db.add(user_token)
        await db.commit()
        await db.refresh(db_user)
        return db_user

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/")
async def activate_user(data: UserActivate, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)

    db_token = await db.execute(
        select(ActivationTokenModel)
        .options(selectinload(ActivationTokenModel.user))
        .where(ActivationTokenModel.token == data.token))
    token = db_token.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < now or token.user.email != data.email:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if token.user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token.user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def request_password_reset(user: UserBase, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalar_one_or_none()

    if db_user and db_user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id))

        new_token = PasswordResetTokenModel(user=db_user)
        db.add(new_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/")
async def password_reset(data: PasswordReset, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id,
            PasswordResetTokenModel.token == data.token
        )
    )
    token = token_result.scalar_one_or_none()

    if not token:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id))
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < now:
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        hashed_password = hash_password(data.password)
        db_user._hashed_password = hashed_password
        await db.delete(token)
        await db.commit()

        return {"message": "Password reset successfully."}

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=LoginResponse, status_code=201)
async def login(
        data: UserLogin,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    payload = {"user_id": db_user.id}
    access_token = jwt_manager.create_access_token(payload)
    refresh_token = jwt_manager.create_refresh_token(payload)

    try:
        db_refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_refresh_token)
        await db.commit()

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=NewAccessToken)
async def refresh_access_token(
        data: UpdateAccessToken,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        refresh_token = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
    db_refresh_token = result.scalar_one_or_none()

    if not db_refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_result = await db.execute(select(UserModel).where(UserModel.id == refresh_token.get("user_id")))
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    payload = {"user_id": user.id}
    new_access_token = jwt_manager.create_access_token(payload)

    return NewAccessToken(access_token=new_access_token)
