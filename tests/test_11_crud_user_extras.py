# tests/test_11_crud_user_extras.py
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone

from app.models.user import User
from app.crud.crud_user import user as crud_user
from app.schemas.user import UserCreate, UserUpdate
from app.core import security

pytestmark = pytest.mark.asyncio

TEST_EMAIL_CRUD = "crudextra@example.com"
TEST_PASSWORD_CRUD = "PasswordCrudExtra123!"
OAUTH_EMAIL = "oauthuser@example.com"

@pytest.fixture(scope="function")
async def setup_user_crud(db_session: AsyncSession) -> User:
    """Fixture to create a standard verified user."""
    user_in = UserCreate(email=TEST_EMAIL_CRUD, password=TEST_PASSWORD_CRUD, full_name="CRUD Extra User")
    user_obj, token = await crud_user.create(db_session, obj_in=user_in)
    # Verify manually
    verified_user = await crud_user.verify_user_email(db_session, token=token)
    assert verified_user is not None
    return verified_user

@pytest.mark.asyncio
async def test_get_or_create_oauth_existing_standard_user(db_session: AsyncSession, setup_user_crud: User):
    """Test get_or_create_by_email_oauth when a standard user already exists."""
    existing_user = setup_user_crud
    original_name = existing_user.full_name
    original_hashed_password = existing_user.hashed_password

    # Call get_or_create with a new name
    retrieved_user = await crud_user.get_or_create_by_email_oauth(
        db_session, email=TEST_EMAIL_CRUD, full_name="New OAuth Name"
    )

    assert retrieved_user is not None
    assert retrieved_user.id == existing_user.id
    assert retrieved_user.email == TEST_EMAIL_CRUD
    # Name should NOT be updated if it already exists
    assert retrieved_user.full_name == original_name
    # Password should remain
    assert retrieved_user.hashed_password == original_hashed_password

@pytest.mark.asyncio
async def test_get_or_create_oauth_existing_oauth_user(db_session: AsyncSession):
    """Test get_or_create_by_email_oauth when an OAuth user already exists."""
    # Create an OAuth user first
    oauth_user_initial = await crud_user.get_or_create_by_email_oauth(
        db_session, email=OAUTH_EMAIL, full_name="OAuth User Initial"
    )
    assert oauth_user_initial is not None
    assert oauth_user_initial.hashed_password is None

    # Call get_or_create again
    retrieved_user = await crud_user.get_or_create_by_email_oauth(
        db_session, email=OAUTH_EMAIL, full_name="OAuth User Second Call"
    )
    assert retrieved_user is not None
    assert retrieved_user.id == oauth_user_initial.id
    # Name should still be the initial one
    assert retrieved_user.full_name == "OAuth User Initial"

@pytest.mark.asyncio
async def test_verify_email_expired_token(db_session: AsyncSession):
    """Test verifying email with an expired token."""
    user_in = UserCreate(email="expiredverify@example.com", password=TEST_PASSWORD_CRUD)
    user_obj, token = await crud_user.create(db_session, obj_in=user_in)

    # Manually expire the token in the DB
    user_obj.verification_token_expires = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    db_session.add(user_obj)
    await db_session.commit()

    verified_user = await crud_user.verify_user_email(db_session, token=token)
    assert verified_user is None

@pytest.mark.asyncio
async def test_reset_password_token_generation_and_get(db_session: AsyncSession, setup_user_crud: User):
    """Test generating and retrieving user by reset token."""
    user = setup_user_crud
    original_hash = user.reset_password_token_hash

    # Generate token
    user_with_token, token_plain = await crud_user.generate_password_reset_token(db_session, user=user)
    assert user_with_token.reset_password_token_hash is not None
    assert user_with_token.reset_password_token_hash != original_hash
    assert user_with_token.reset_password_token_expires is not None

    # Get user by token
    retrieved_user = await crud_user.get_user_by_reset_token(db_session, token=token_plain)
    assert retrieved_user is not None
    assert retrieved_user.id == user.id

    # Test get with invalid token
    retrieved_invalid = await crud_user.get_user_by_reset_token(db_session, token="invalid")
    assert retrieved_invalid is None

@pytest.mark.asyncio
async def test_reset_password_token_expired(db_session: AsyncSession, setup_user_crud: User):
    """Test retrieving user by expired reset token."""
    user = setup_user_crud
    _, token_plain = await crud_user.generate_password_reset_token(db_session, user=user)

    # Manually expire the token
    user.reset_password_token_expires = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    db_session.add(user)
    await db_session.commit()

    retrieved_user = await crud_user.get_user_by_reset_token(db_session, token=token_plain)
    assert retrieved_user is None

@pytest.mark.asyncio
async def test_reset_password_inactive_user(db_session: AsyncSession, setup_user_crud: User):
    """Test retrieving user by reset token when user is inactive."""
    user = setup_user_crud
    _, token_plain = await crud_user.generate_password_reset_token(db_session, user=user)

    # Deactivate user
    user.is_active = False
    db_session.add(user)
    await db_session.commit()

    # Should not find the user because is_active check fails
    retrieved_user = await crud_user.get_user_by_reset_token(db_session, token=token_plain)
    assert retrieved_user is None