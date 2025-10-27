# auth_api/app/api/endpoints/mgmt.py
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status, Body, Path
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_db
from app.crud.crud_user import user as crud_user
from app.models.user import User
from app.schemas.user import User as UserSchema
import re # Para checagem de email

router = APIRouter()

async def get_user_by_id_or_email(
    db: AsyncSession = Depends(get_db),
    user_id_or_email: str = Path(...)
) -> User:
    """
    Dependência que busca um usuário pelo seu ID ou Email.
    Usado pelos endpoints de /mgmt.
    """
    user = None
    # Verifica se parece um email
    if re.match(r"[^@]+@[^@]+\.[^@]+", user_id_or_email):
        user = await crud_user.get_by_email(db, email=user_id_or_email)
    else:
        # Tenta buscar por ID
        try:
            user_id = int(user_id_or_email)
            user = await crud_user.get(db, id=user_id)
        except ValueError:
            # Não é um email válido nem um ID numérico
            pass
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    return user


@router.patch(
    "/users/{user_id_or_email}/claims",
    response_model=UserSchema,
)
async def update_user_claims(
    *,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_user_by_id_or_email), # Usa a dependência helper
    claims_in: Dict[str, Any] = Body(...) # Pega o JSON do corpo
) -> Any:
    """
    Atualiza (mescla) os claims customizados de um usuário (ex: roles, permissions).
    Este endpoint é protegido pela X-API-Key (definido no main.py).
    
    Exemplo de Body:
    {
        "roles": ["admin", "user"],
        "permissions": ["read:products", "write:products"],
        "store_id": 123
    }
    """
    updated_user = await crud_user.update_custom_claims(
        db, user=user, claims=claims_in
    )
    return updated_user