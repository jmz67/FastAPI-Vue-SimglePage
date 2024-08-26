# JWT 认证
在添加路由处理程序之前，让我们先设置认证机制来保护特定路由。

首先，我们需要在`"services/backend/src/schemas"`文件夹中新建一个文件`token.py`，并创建几个Pydantic模型：

```python
from typing import Optional  # 从 typing 模块导入 Optional，用于指定属性可以是 None

from pydantic import BaseModel  # 从 pydantic 模块导入 BaseModel，用于定义数据模型


class TokenData(BaseModel):  # 定义一个 TokenData 类，用于表示从 JWT 令牌中提取的数据
    username: Optional[str] = None  # 定义一个可选的字符串属性 username，默认为 None


class Status(BaseModel):  # 定义一个 Status 类，用于发送状态消息给终端用户
    message: str  # 定义一个字符串属性 message，用于存储状态消息
```

我们定义了两个模式（schemas）：
- `TokenData`用于确保从令牌中提取出的`username`是一个字符串。
- `Status`用于向终端用户发送状态消息。

在`"services/backend/src"`文件夹中创建一个名为`"auth"`的新文件夹。然后，在该文件夹中添加两个新文件，分别命名为`jwthandler.py`和`users.py`。

#### services/backend/src/auth/jwthandler.py

```python
import os  # 导入 os 模块，用于访问操作系统的环境变量
from datetime import datetime, timedelta  # 从 datetime 模块导入 datetime 和 timedelta，用于处理时间
from typing import Optional  # 从 typing 模块导入 Optional，用于类型注解中表示可选值

from fastapi import Depends, HTTPException, Request  # 从 fastapi 导入 Depends, HTTPException 和 Request 类
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel  # 导入 OAuthFlows 模型，用于 OAuth2 认证
from fastapi.security import OAuth2  # 从 fastapi.security 导入 OAuth2 类
from fastapi.security.utils import get_authorization_scheme_param  # 导入获取认证方案的实用函数
from jose import JWTError, jwt  # 从 python-jose 导入 JWTError 和 jwt，用于处理 JWT 令牌
from tortoise.exceptions import DoesNotExist  # 从 tortoise.exceptions 导入 DoesNotExist 异常

from src.schemas.token import TokenData  # 导入我们之前在 token.py 中定义的 TokenData 模型
from src.schemas.users import UserOutSchema  # 导入我们之前定义的 UserOutSchema 模型
from src.database.models import Users  # 导入数据库模型中的 Users 表

# 从环境变量中获取密钥
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"  # 定义 JWT 使用的加密算法
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 定义访问令牌的有效期为 30 分钟


# 定义一个继承自 OAuth2 的类，用于基于 Cookie 的 OAuth2 认证
class OAuth2PasswordBearerCookie(OAuth2):
    def __init__(
        self,
        token_url: str,
        scheme_name: str = None,
        scopes: dict = None,
        auto_error: bool = True,
    ):
        if not scopes:  # 如果没有提供 scopes，则初始化为空字典
            scopes = {}
        # 使用密码流来生成 OAuthFlowsModel 对象
        flows = OAuthFlowsModel(password={"tokenUrl": token_url, "scopes": scopes})
        # 调用父类的构造函数，初始化 OAuth2 类
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        # 从请求中获取存储在 Cookies 中的 "Authorization" 信息
        authorization: str = request.cookies.get("Authorization")
        # 获取认证方案和参数（例如 Bearer 令牌）
        scheme, param = get_authorization_scheme_param(authorization)

        # 如果 Authorization 为空或方案不是 "bearer"，则返回未认证错误
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:  # 如果设置了自动抛出错误
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",  # 详细说明未认证的错误
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None  # 否则返回 None

        return param  # 返回提取的 token


# 实例化 OAuth2PasswordBearerCookie 类，设置 token 的获取路径为 "/login"
security = OAuth2PasswordBearerCookie(token_url="/login")


# 定义一个函数来创建访问令牌
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()  # 复制输入数据，以免修改原始数据

    # 如果传入了有效期，则使用该有效期
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        # 否则默认为 15 分钟后过期
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})  # 在要编码的数据中添加过期时间
    # 使用 SECRET_KEY 和 ALGORITHM 对数据进行加密，生成 JWT
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt  # 返回生成的 JWT


# 定义一个异步函数来获取当前用户
async def get_current_user(token: str = Depends(security)):
    # 如果凭据无效，抛出 HTTP 401 错误
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",  # 错误详细说明
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # 解码 JWT，获取 payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # 从 payload 中提取用户名
        username: str = payload.get("sub")
        if username is None:  # 如果用户名为空，则抛出凭据异常
            raise credentials_exception
        # 创建一个 TokenData 实例，包含提取到的用户名
        token_data = TokenData(username=username)
    except JWTError:  # 如果解码失败，抛出凭据异常
        raise credentials_exception

    try:
        # 从数据库中获取用户信息
        user = await UserOutSchema.from_queryset_single(
            Users.get(username=token_data.username)
        )
    except DoesNotExist:  # 如果用户不存在，抛出凭据异常
        raise credentials_exception

    return user  # 返回用户信息
```

**笔记：**
- `OAuth2PasswordBearerCookie`是一个从`OAuth2`继承的类，用于从请求头中读取用于保护路由的 Cookie。它确保 Cookie 存在并返回 Cookie 中的 token。
- `create_access_token`函数接收用户的用户名，将其与到期时间一起编码，并生成一个 token。
- `get_current_user`解码 token 并验证用户。

使用`python-jose`进行 JWT token 的编码和解码。将该包添加到`requirements`文件中：

```text
aerich==0.7.1
asyncpg==0.27.0
bcrypt==4.0.1
passlib==1.7.4
fastapi==0.88.0
python-jose==3.3.0
tortoise-orm==0.19.2
uvicorn==0.20.0
```

将`SECRET_KEY`环境变量添加到`docker-compose.yml`文件中：

```yaml
version: '3.8'

services:

  backend:
    build: ./services/backend
    ports:
      - 5000:5000
    environment:
      - DATABASE_URL=postgres://hello_fastapi:hello_fastapi@db:5432/hello_fastapi_dev
      - SECRET_KEY=09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7
    volumes:
      - ./services/backend:/app
    command: uvicorn src.main:app --reload --host 0.0.0.0 --port 5000
    depends_on:
      - db

  frontend:
    build: ./services/frontend
    volumes:
      - './services/frontend:/app'
      - '/app/node_modules'
    ports:
      - 8080:8080

  db:
    image: postgres:15.1
    expose:
      - 5432
    environment:
      - POSTGRES_USER=hello_fastapi
      - POSTGRES_PASSWORD=hello_fastapi
      - POSTGRES_DB=hello_fastapi_dev
    volumes:
      - postgres_data:/var/lib/postgresql/data/

volumes:
  postgres_data:
```

#### services/backend/src/auth/users.py

```python
from fastapi import HTTPException, Depends, status  # 从 fastapi 导入 HTTPException, Depends 和 status 模块
from fastapi.security import OAuth2PasswordRequestForm  # 从 fastapi.security 导入 OAuth2PasswordRequestForm 类
from passlib.context import CryptContext  # 从 passlib.context 导入 CryptContext 类，用于加密密码
from tortoise.exceptions import DoesNotExist  # 从 tortoise.exceptions 导入 DoesNotExist 异常

from src.database.models import Users  # 导入数据库模型中的 Users 表
from src.schemas.users import UserDatabaseSchema  # 导入我们定义的 UserDatabaseSchema 模型


# 创建一个 CryptContext 实例，用于定义密码加密和解密的算法
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    """
    验证给定的明文密码是否与已哈希的密码匹配。

    :param plain_password: 明文密码
    :param hashed_password: 已哈希的密码
    :return: 布尔值，表示密码是否匹配
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """
    将明文密码哈希化。

    :param password: 明文密码
    :return: 哈希化后的密码
    """
    return pwd_context.hash(password)


async def get_user(username: str):
    """
    根据用户名从数据库中获取用户信息。

    :param username: 用户名
    :return: UserDatabaseSchema 对象
    """
    return await UserDatabaseSchema.from_queryset_single(Users.get(username=username))


async def validate_user(user: OAuth2PasswordRequestForm = Depends()):
    """
    验证用户的用户名和密码是否正确。如果用户名或密码不正确，抛出 401 错误。

    :param user: OAuth2PasswordRequestForm 对象，包含用户名和密码
    :return: 验证成功的用户对象
    """
    try:
        db_user = await get_user(user.username)  # 从数据库中获取用户信息
    except DoesNotExist:  # 如果用户不存在，抛出 401 错误
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not verify_password(user.password, db_user.password):  # 如果密码不匹配，抛出 401 错误
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    return db_user  # 返回用户对象
```

**笔记：**
- `verify_password`函数用于验证明文密码与哈希密码是否匹配。
- `get_password_hash`函数用于将明文密码哈希化。
- `get_user`函数从数据库中获取用户信息。
- `validate_user`函数用于验证用户登录请求中的用户名和密码是否正确。如果用户名或密码不正确，抛出`401_UNAUTHORIZED`错误。

#### 更新 CRUD 助手以使用 Status Pydantic 模型

**services/backend/src/crud/users.py**

```python
from fastapi import HTTPException  # 从 fastapi 导入 HTTPException 类
from passlib.context import CryptContext  # 从 passlib.context 导入 CryptContext 类，用于密码加密
from tortoise.exceptions import DoesNotExist, IntegrityError  # 从 tortoise.exceptions 导入 DoesNotExist 和 IntegrityError 异常

from src.database.models import Users  # 导入数据库模型中的 Users 表
from src.schemas.token import Status  # 导入我们定义的 Status 模型
from src.schemas.users import UserOutSchema  # 导入我们定义的 UserOutSchema 模型


# 创建一个 CryptContext 实例，用于定义密码加密和解密的算法
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def create_user(user) -> UserOutSchema:
    """
    创建一个新用户。

    :param user: 用户对象
    :return: 创建成功的用户对象
    """
    user.password = pwd_context.encrypt(user.password)  # 哈希化用户密码

    try:
        user_obj = await Users.create(**user.dict(exclude_unset=True))  # 在数据库中创建用户
    except IntegrityError:  # 如果用户名已存在，抛出 401 错误
        raise HTTPException(status_code=401, detail="Sorry, that username already exists.")

    return await UserOutSchema.from_tortoise_orm(user_obj)  # 返回创建的用户对象


async def delete_user(user_id, current_user) -> Status:
    """
    删除用户。

    :param user_id: 用户 ID
    :param current_user: 当前登录的用户对象
    :return: 包含删除状态消息的 Status 对象
    """
    try:
        db_user = await UserOutSchema.from_queryset_single(Users.get(id=user_id))  # 获取用户信息
    except DoesNotExist:  # 如果用户不存在，抛出 404 错误
        raise HTTPException(status_code=404, detail=f"User {user_id} not found")

    if db_user.id == current_user.id:  # 如果要删除的用户是当前用户
        deleted_count = await Users.filter(id=user_id).delete()  # 从数据库中删除用户
        if not deleted_count:  # 如果删除操作未成功，抛出 404 错误
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        return Status(message=f"Deleted user {user_id}")  # 返回删除状态消息

    raise HTTPException(status_code=403, detail="Not authorized to delete")  # 如果当前用户没有权限删除，抛出 403 错误
```

**services/backend/src/crud/notes.py**

```python
from fastapi import HTTPException  # 从 fastapi 导入 HTTPException 类
from tortoise.exceptions import DoesNotExist  # 从 tortoise.exceptions 导入 DoesNotExist 异常

from src.database.models import Notes  # 导入数据库模型中的 Notes 表
from src.schemas.notes import NoteOutSchema  # 导入我们定义的 NoteOutSchema 模型
from src.schemas.token import Status  # 导入我们定义的 Status 模型


async def get_notes():
    """
    获取所有笔记。

    :return: NoteOutSchema 对象的列表
    """
    return await NoteOutSchema.from_queryset(Notes.all())  # 从数据库中获取所有笔记并返回


async def get_note(note_id) -> NoteOutSchema:
    """
    根据笔记 ID 获取单个笔记。

    :param note_id: 笔记 ID
    :return: NoteOutSchema 对象
    """
    return await NoteOutSchema.from_queryset_single(Notes.get(id=note_id))  # 从数据库中获取指定 ID 的笔记并返回


async def create_note(note, current_user) -> NoteOutSchema:
    """
    创建一条新笔记。

    :param note: 笔记对象
    :param current_user: 当前登录的用户对象
    :return: 创建成功的 NoteOutSchema 对象
    """
    note_dict = note.dict(exclude_unset=True)  # 将笔记对象转换为字典
    note_dict["author_id"] = current_user.id  # 设置笔记的作者为当前用户
    note_obj = await Notes.create(**note_dict)  # 在数据库中创建笔记
    return await NoteOutSchema.from_tortoise_orm(note_obj)  # 返回创建的笔记对象


async def update_note(note_id, note, current_user) -> NoteOutSchema:
    """
    更新指定 ID 的笔记。

    :param note_id: 笔记 ID
    :param note: 笔记对象
    :param current_user: 当前登录的用户对象
    :return: 更新后的 NoteOutSchema 对象
    """
    try:
        db_note = await NoteOutSchema.from_queryset_single(Notes.get(id=note_id))  # 获取笔记信息
    except DoesNotExist:  # 如果笔记不存在，抛出 404 错误
        raise HTTPException(status_code=404, detail=f"Note {note_id} not found")

    if db_note.author.id == current_user.id:  # 如果笔记的作者是当前用户
        await Notes.filter(id=note_id).update(**note.dict(exclude_unset=True))  # 更新笔记信息
        return await NoteOutSchema.from_queryset_single(Notes.get(id=note_id))  # 返回更新后的笔记对象

    raise HTTPException(status_code=403, detail="Not authorized to update")  # 如果当前用户没有权限更新，抛出 403 错误


async def delete_note(note_id, current_user) -> Status:
    """
    删除指定 ID 的笔记。

    :param note_id: 笔记 ID
    :param current_user: 当前登录的用户对象
    :return: 包含删除状态消息的 Status 对象
    """
    try:
        db_note = await NoteOutSchema.from_queryset_single(Notes.get(id=note_id))  # 获取笔记信息
    except DoesNotExist:  # 如果笔记不存在，抛出 404 错误
        raise HTTPException(status_code=404, detail=f"Note {note_id} not found")

    if db_note.author.id == current_user.id:  # 如果笔记的作者是当前用户
        deleted_count = await Notes.filter(id=note_id).delete()  # 从数据库中删除笔记
        if not deleted_count:  # 如果删除操作未成功，抛出 404 错误
            raise HTTPException(status_code=404, detail=f"Note {note_id} not found")
        return Status(message=f"Deleted note {note_id}")  # 返回删除状态消息

    raise HTTPException(status_code=403, detail="Not authorized to delete")  # 如果当前用户没有权限删除，抛出 403 错误
```

**注释：**
- `delete_note` 函数用于删除指定 ID 的笔记。
  - `note_id`: 需要删除的笔记 ID。
  - `current_user`: 当前登录的用户对象。
  - 首先尝试从数据库中获取指定 ID 的笔记，如果笔记不存在，抛出 `404` 错误。
  - 检查笔记的作者是否为当前用户，如果是，则删除笔记并返回状态消息。如果删除操作失败，则抛出 `404` 错误。
  - 如果当前用户没有权限删除笔记，抛出 `403` 错误。

