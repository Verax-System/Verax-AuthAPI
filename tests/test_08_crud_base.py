# tests/test_08_crud_base.py
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.user import User
from app.crud.crud_user import user as crud_user # Use the specific instance
from app.schemas.user import UserCreate, UserUpdate

pytestmark = pytest.mark.asyncio

TEST_EMAIL_BASE = "crudbase@example.com"
TEST_PASSWORD_BASE = "PasswordCrud123!"

@pytest.fixture(scope="function")
async def setup_user(db_session: AsyncSession) -> User:
    """Fixture to create a single user for GET/UPDATE/REMOVE tests."""
    user_in = UserCreate(email=TEST_EMAIL_BASE, password=TEST_PASSWORD_BASE, full_name="CRUD Base User")
    # Directly use CRUD method, bypass API for setup
    user_obj, _ = await crud_user.create(db_session, obj_in=user_in)
    # Manually activate for simplicity in update/delete tests
    user_obj.is_active = True
    user_obj.is_verified = True
    db_session.add(user_obj)
    await db_session.commit()
    await db_session.refresh(user_obj)
    return user_obj

@pytest.mark.asyncio
async def test_crud_base_get(db_session: AsyncSession, setup_user: User):
    """Test CRUDBase get method."""
    user_id = setup_user.id
    retrieved_user = await crud_user.get(db_session, id=user_id)
    assert retrieved_user is not None
    assert retrieved_user.id == user_id
    assert retrieved_user.email == TEST_EMAIL_BASE

    # Test get non-existent
    non_existent_user = await crud_user.get(db_session, id=99999)
    assert non_existent_user is None

@pytest.mark.asyncio
async def test_crud_base_get_multi(db_session: AsyncSession):
    """Test CRUDBase get_multi method with skip and limit."""
    # Create multiple users
    users_to_create = 5
    for i in range(users_to_create):
        email = f"multi_{i}@example.com"
        user_in = UserCreate(email=email, password=TEST_PASSWORD_BASE, full_name=f"Multi User {i}")
        await crud_user.create(db_session, obj_in=user_in)

    # Test get_multi default (limit 100)
    all_users = await crud_user.get_multi(db_session)
    assert len(all_users) == users_to_create

    # Test limit
    limited_users = await crud_user.get_multi(db_session, limit=2)
    assert len(limited_users) == 2

    # Test skip
    skipped_users = await crud_user.get_multi(db_session, skip=3)
    assert len(skipped_users) == users_to_create - 3

    # Test skip and limit
    skip_limit_users = await crud_user.get_multi(db_session, skip=1, limit=2)
    assert len(skip_limit_users) == 2
    # Ensure the correct users were skipped/limited (emails should reflect index)
    assert skip_limit_users[0].email == "multi_1@example.com"
    assert skip_limit_users[1].email == "multi_2@example.com"

@pytest.mark.asyncio
async def test_crud_base_update(db_session: AsyncSession, setup_user: User):
    """Test CRUDBase update method."""
    user_id = setup_user.id
    update_schema = UserUpdate(full_name="Updated Name", is_active=False)

    updated_user = await crud_user.update(db_session, db_obj=setup_user, obj_in=update_schema)
    assert updated_user is not None
    assert updated_user.id == user_id
    assert updated_user.full_name == "Updated Name"
    assert updated_user.is_active is False
    assert updated_user.email == TEST_EMAIL_BASE # Email should not change unless provided

    # Verify in DB
    refreshed_user = await db_session.get(User, user_id)
    assert refreshed_user.full_name == "Updated Name"
    assert refreshed_user.is_active is False

    # Test update with dict
    update_dict = {"full_name": "Updated Again"}
    updated_again_user = await crud_user.update(db_session, db_obj=refreshed_user, obj_in=update_dict)
    assert updated_again_user.full_name == "Updated Again"

@pytest.mark.asyncio
async def test_crud_base_remove(db_session: AsyncSession, setup_user: User):
    """Test CRUDBase remove method."""
    user_id = setup_user.id

    # Remove existing user
    removed_user = await crud_user.remove(db_session, id=user_id)
    assert removed_user is not None
    assert removed_user.id == user_id

    # Verify removed from DB
    user_in_db = await db_session.get(User, user_id)
    assert user_in_db is None

    # Try removing non-existent user
    removed_non_existent = await crud_user.remove(db_session, id=99999)
    assert removed_non_existent is None