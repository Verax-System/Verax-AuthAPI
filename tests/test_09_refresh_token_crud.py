# tests/test_09_refresh_token_crud.py
import pytest
from httpx import AsyncClient # Import AsyncClient if needed, though not used directly here
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone

from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.crud import crud_refresh_token
# --- CORREÇÃO: Adicionar import ---
from app.crud.crud_user import user as crud_user
# --- FIM CORREÇÃO ---
from app.core import security
from app.schemas.user import UserCreate

pytestmark = pytest.mark.asyncio

TEST_EMAIL_REFRESH = "refreshtokencrud@example.com" # Use a different email
TEST_PASSWORD_REFRESH = "PasswordRefreshCrud123!"

@pytest.fixture(scope="function")
async def setup_user_refresh(db_session: AsyncSession) -> User:
    """Fixture to create/reset a user for refresh token tests."""
    # Check if user exists
    user_result = await db_session.execute(select(User).where(User.email == TEST_EMAIL_REFRESH))
    user_obj = user_result.scalars().first()

    if not user_obj:
        user_in = UserCreate(email=TEST_EMAIL_REFRESH, password=TEST_PASSWORD_REFRESH, full_name="Refresh Crud User")
        # Use o crud_user importado corretamente
        user_obj, _ = await crud_user.create(db_session, obj_in=user_in)
    else:
        # Reset password just in case
        user_obj.hashed_password = security.get_password_hash(TEST_PASSWORD_REFRESH)

    user_obj.is_active = True
    user_obj.is_verified = True
    db_session.add(user_obj)
    await db_session.commit()
    await db_session.refresh(user_obj)
    return user_obj

@pytest.mark.asyncio
async def test_create_and_get_refresh_token(db_session: AsyncSession, setup_user_refresh: User):
    """Test creating and retrieving a valid refresh token."""
    user = setup_user_refresh
    token_str, expires_at_naive = security.create_refresh_token(data={"sub": str(user.id)})

    # create_refresh_token implicitly clears old tokens
    db_token = await crud_refresh_token.create_refresh_token(
        db_session, user=user, token=token_str, expires_at=expires_at_naive
    )
    assert db_token is not None
    assert db_token.user_id == user.id
    # Compare naive datetimes, potentially adjusting for minor precision differences if needed
    assert abs(db_token.expires_at - expires_at_naive) < timedelta(seconds=1)

    # Get the token back
    retrieved_token = await crud_refresh_token.get_refresh_token(db_session, token=token_str)
    assert retrieved_token is not None
    assert retrieved_token.id == db_token.id
    assert retrieved_token.token_hash == crud_refresh_token.hash_token(token_str)
    assert retrieved_token.is_revoked is False

    # Test get with invalid token
    invalid_retrieved = await crud_refresh_token.get_refresh_token(db_session, token="invalidtoken")
    assert invalid_retrieved is None

@pytest.mark.asyncio
async def test_revoke_refresh_token(db_session: AsyncSession, setup_user_refresh: User):
    """Test revoking a refresh token."""
    user = setup_user_refresh
    token_str, expires_at = security.create_refresh_token(data={"sub": str(user.id)})
    await crud_refresh_token.create_refresh_token(
        db_session, user=user, token=token_str, expires_at=expires_at
    )

    # Revoke
    revoked = await crud_refresh_token.revoke_refresh_token(db_session, token=token_str)
    assert revoked is True

    # Try to get again (should fail as it's revoked)
    retrieved_token = await crud_refresh_token.get_refresh_token(db_session, token=token_str)
    assert retrieved_token is None

    # Try revoking again (should return False)
    revoked_again = await crud_refresh_token.revoke_refresh_token(db_session, token=token_str)
    assert revoked_again is False

    # Try revoking non-existent token
    revoked_non_existent = await crud_refresh_token.revoke_refresh_token(db_session, token="nonexistent")
    assert revoked_non_existent is False

@pytest.mark.asyncio
async def test_revoke_all_for_user(db_session: AsyncSession, setup_user_refresh: User):
    """Test revoking all tokens for a user."""
    user = setup_user_refresh
    # Create multiple tokens for the SAME user (create_refresh_token handles clearing)
    token1_str, exp1 = security.create_refresh_token(data={"sub": str(user.id)})
    await crud_refresh_token.create_refresh_token(db_session, user=user, token=token1_str, expires_at=exp1)
    # The second call will replace the first one due to the delete logic in create_refresh_token
    token2_str, exp2 = security.create_refresh_token(data={"sub": str(user.id), "jti": "some_jti"})
    await crud_refresh_token.create_refresh_token(db_session, user=user, token=token2_str, expires_at=exp2)

    # Verify only the second token exists before revoke_all
    retrieved1_before = await crud_refresh_token.get_refresh_token(db_session, token=token1_str)
    retrieved2_before = await crud_refresh_token.get_refresh_token(db_session, token=token2_str)
    assert retrieved1_before is None
    assert retrieved2_before is not None

    # Revoke all for the user
    count = await crud_refresh_token.revoke_all_refresh_tokens_for_user(db_session, user_id=user.id)
    assert count == 1 # Only one token (token2) was active to be revoked

    # Verify all are gone/revoked
    retrieved1_after = await crud_refresh_token.get_refresh_token(db_session, token=token1_str)
    retrieved2_after = await crud_refresh_token.get_refresh_token(db_session, token=token2_str)
    assert retrieved1_after is None
    assert retrieved2_after is None

    # Test revoke all for user with no tokens
    count_none = await crud_refresh_token.revoke_all_refresh_tokens_for_user(db_session, user_id=9999) # Non-existent user ID
    assert count_none == 0

@pytest.mark.asyncio
async def test_prune_expired_tokens(db_session: AsyncSession, setup_user_refresh: User):
    """Test pruning (deleting) expired tokens."""
    user = setup_user_refresh
    now_utc = datetime.now(timezone.utc)
    now_naive = now_utc.replace(tzinfo=None)

    # Create one valid, one expired token directly in DB for testing prune
    valid_token_str, valid_exp = security.create_refresh_token(data={"sub": str(user.id)})
    expired_token_str, _ = security.create_refresh_token(data={"sub": str(user.id), "jti": "expired"})
    expired_exp_naive = now_naive - timedelta(days=1) # Clearly expired

    # Create the valid one using the CRUD function (clears previous if any)
    await crud_refresh_token.create_refresh_token(db_session, user=user, token=valid_token_str, expires_at=valid_exp)

    # Manually insert the expired one AFTER the valid one
    expired_hash = crud_refresh_token.hash_token(expired_token_str)
    expired_db_token = RefreshToken(user_id=user.id, token_hash=expired_hash, expires_at=expired_exp_naive, is_revoked=False)
    db_session.add(expired_db_token)
    await db_session.commit() # Commit the expired token

    # Prune expired tokens
    pruned_count = await crud_refresh_token.prune_expired_tokens(db_session)
    assert pruned_count >= 1 # Should prune at least the one we added

    # Verify valid token still exists
    valid_retrieved = await crud_refresh_token.get_refresh_token(db_session, token=valid_token_str)
    assert valid_retrieved is not None

    # Verify expired token is gone from DB
    expired_check = await db_session.execute(select(RefreshToken).where(RefreshToken.token_hash == expired_hash))
    assert expired_check.scalars().first() is None