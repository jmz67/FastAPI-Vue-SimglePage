# CRUD 操作


现在让我们设置基本的 CRUD 操作：创建（Create）、读取（Read）、更新（Update）和删除（Delete）。

首先，由于我们需要定义用于序列化和反序列化数据的模式，请在 `"services/backend/src"` 文件夹中创建两个文件夹，分别命名为 `"crud"` 和 `"schemas"`。

为了确保我们的序列化程序能够读取模型之间的关系，我们需要在 `main.py` 文件中初始化模型：

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from tortoise import Tortoise  # 新增行

from src.database.register import register_tortoise
from src.database.config import TORTOISE_ORM


# 启用 schemas 读取模型之间的关系
Tortoise.init_models(["src.database.models"], "models")  # 新增行

app = FastAPI()

# 配置 CORS 中间件，允许指定的源（此处为本地）访问 API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],  # 允许的跨域请求来源
    allow_credentials=True,  # 允许发送 Cookie
    allow_methods=["*"],  # 允许的 HTTP 方法（如 GET, POST 等）
    allow_headers=["*"],  # 允许的 HTTP 请求头
)

# 注册 Tortoise ORM，并与 FastAPI 应用结合
register_tortoise(app, config=TORTOISE_ORM, generate_schemas=False)


@app.get("/")
def home():
    return "Hello, World!"  # 定义根路径的简单响应
```

现在，对任意对象的查询都可以从相关表中获取数据。

接下来，在 `"schemas"` 文件夹中，添加两个文件：`users.py` 和 `notes.py`。

`services/backend/src/schemas/users.py`:

```python
from tortoise.contrib.pydantic import pydantic_model_creator

from src.database.models import Users


# 用于创建新用户的 schema，排除了只读字段
UserInSchema = pydantic_model_creator(
    Users, name="UserIn", exclude_readonly=True
)

# 用于返回给终端用户的用户信息 schema，排除了一些敏感或不需要的字段
UserOutSchema = pydantic_model_creator(
    Users, name="UserOut", exclude=["password", "created_at", "modified_at"]
)

# 用于在应用内部使用的用户信息 schema，排除了一些不必要的字段
UserDatabaseSchema = pydantic_model_creator(
    Users, name="User", exclude=["created_at", "modified_at"]
)
```

`pydantic_model_creator` 是一个 Tortoise 提供的辅助工具，它允许我们从 Tortoise 模型创建 Pydantic 模型，这些模型将用于创建和检索数据库记录。
它接收 `Users` 模型和一个名称作为参数。你还可以排除特定的列。

### 模式说明：

- `UserInSchema` 用于创建新用户。
- `UserOutSchema` 用于检索用户信息，并返回给终端用户。
- `UserDatabaseSchema` 用于在应用内部检索用户信息，进行用户验证。

`services/backend/src/schemas/notes.py`:

```python
from typing import Optional

from pydantic import BaseModel
from tortoise.contrib.pydantic import pydantic_model_creator

from src.database.models import Notes


# 用于创建新笔记的 schema，排除了 "author_id" 字段，并且排除了只读字段
NoteInSchema = pydantic_model_creator(
    Notes, name="NoteIn", exclude=["author_id"], exclude_readonly=True)

# 用于检索笔记的 schema，排除了某些不必要的或敏感的字段
NoteOutSchema = pydantic_model_creator(
    Notes, name="Note", exclude =[
      "modified_at", "author.password", "author.created_at", "author.modified_at"
    ]
)


class UpdateNote(BaseModel):
    title: Optional[str]  # 标题字段，可选
    content: Optional[str]  # 内容字段，可选
```

### 模式说明：

- `NoteInSchema` 用于创建新笔记。
- `NoteOutSchema` 用于检索笔记。
- `UpdateNote` 用于更新笔记。

接下来，在 `"services/backend/src/crud"` 文件夹中添加 `users.py` 和 `notes.py` 文件。

`services/backend/src/crud/users.py`:

```python
from fastapi import HTTPException
from passlib.context import CryptContext  # 用于处理密码加密
from tortoise.exceptions import DoesNotExist, IntegrityError  # 处理数据库操作中的异常

from src.database.models import Users
from src.schemas.users import UserOutSchema


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  # 配置密码加密算法


async def create_user(user) -> UserOutSchema:
    user.password = pwd_context.encrypt(user.password)  # 对用户密码进行加密

    try:
        # 尝试在数据库中创建用户对象
        user_obj = await Users.create(**user.dict(exclude_unset=True))
    except IntegrityError:
        # 如果出现用户名冲突，抛出 HTTP 异常
        raise HTTPException(status_code=401, detail=f"抱歉，该用户名已存在。")

    # 将创建的用户对象转换为 UserOutSchema 类型并返回
    return await UserOutSchema.from_tortoise_orm(user_obj)


async def delete_user(user_id, current_user):
    try:
        # 尝试从数据库中获取要删除的用户对象
        db_user = await UserOutSchema.from_queryset_single(Users.get(id=user_id))
    except DoesNotExist:
        # 如果用户不存在，抛出 HTTP 异常
        raise HTTPException(status_code=404, detail=f"用户 {user_id} 未找到")

    if db_user.id == current_user.id:
        # 如果删除的用户与当前用户匹配，执行删除操作
        deleted_count = await Users.filter(id=user_id).delete()
        if not deleted_count:
            raise HTTPException(status_code=404, detail=f"用户 {user_id} 未找到")
        return f"已删除用户 {user_id}"

    # 如果当前用户无权删除该用户，抛出 HTTP 异常
    raise HTTPException(status_code=403, detail=f"无权删除")
```

在这里，我们定义了用于创建和删除用户的辅助函数：

- `create_user` 接收一个用户对象，对 `user.password` 进行加密，然后将用户添加到数据库中。
- `delete_user` 从数据库中删除用户。它还通过确保请求由当前已认证的用户发起来保护用户。

将所需的依赖项添加到 `services/backend/requirements.txt` 中：

```plaintext
aerich==0.7.1
asyncpg==0.27.0
bcrypt==4.0.1
passlib==1.7.4
fastapi==0.88.0
tortoise-orm==0.19.2
uvicorn==0.20.0
```

`services/backend/src/crud/notes.py`:

```python
from fastapi import HTTPException
from tortoise.exceptions import DoesNotExist

from src.database.models import Notes
from src.schemas.notes import NoteOutSchema


async def get_notes():
    # 获取所有笔记并转换为 NoteOutSchema 类型的列表
    return await NoteOutSchema.from_queryset(Notes.all())


async def get_note(note_id) -> NoteOutSchema:
    # 获取单个笔记并转换为 NoteOutSchema 类型
    return await NoteOutSchema.from_queryset_single(Notes.get(id=note_id))


async def create_note(note, current_user) -> NoteOutSchema:
    note_dict = note.dict(exclude_unset=True)  # 转换为字典，并排除未设置的字段
    note_dict["author_id"] = current_user.id  # 设置笔记的作者 ID
    note_obj = await Notes.create(**note_dict)  # 创建笔记对象
    return await NoteOutSchema.from_tortoise_orm(note_obj)  # 返回创建的笔记对象


async def update_note(note_id, note, current_user) -> NoteOutSchema:
    try:
        # 获取要更新的笔记
        db_note = await NoteOutSchema.from_queryset_single(Notes.get(id=note_id))
    except DoesNotExist:
        # 如果笔记不存在，抛出 HTTP 异常
        raise HTTPException(status_code=404, detail=f"笔记 {note_id} 未找到")

    if db_note.author.id == current_user.id:
        # 如果当前用户是笔记的作者，执行更新操作
        await Notes.filter(id=note_id).update(**note.dict(exclude_unset=True))
        return await NoteOutSchema.from_queryset_single(Notes.get(id=note_id))

    # 如果当前用户无权更新该笔记，抛出 HTTP 异常
    raise HTTPException(status_code=403, detail=f"无权更新")


async def delete_note(note_id, current_user):
    try:
        # 获取要删除的笔记
        db_note = await NoteOutSchema.from_queryset_single(Notes.get(id=note_id))
    except DoesNotExist:
        # 如果笔记不存在，抛出 HTTP 异常
        raise HTTPException(status_code=404, detail=f"笔记 {note_id} 未找到")

    if db_note.author.id == current_user.id:
        # 如果当前用户是笔记的作者，执行删除操作
        deleted_count = await Notes.filter(id=note_id).delete()
        if not deleted_count:
            # 如果删除操作未成功，抛出 HTTP 异常
            raise HTTPException(status_code=404, detail=f"笔记 {note_id} 未找到")
        return f"已删除笔记 {note_id}"

    # 如果当前用户无权删除该笔记，抛出 HTTP 异常
    raise HTTPException(status_code=403, detail=f"无权删除")
```

在这个部分，我们创建了用于实现笔记资源的所有 CRUD 操作的辅助函数。需要注意 `update_note` 和 `delete_note` 辅助函数中，加入了检查，以确保请求来自笔记的作者。

---

### 目录结构

您的目录结构现在应如下所示：

```
├── docker-compose.yml
└── services
    ├── backend
    │   ├── Dockerfile
    │   ├── migrations
    │   │   └── models
    │   │       └── 0_20221212182213_init.py
    │   ├── pyproject.toml
    │   ├── requirements.txt
    │   └── src
    │       ├── crud
    │       │   ├── notes.py
    │       │   └── users.py
    │       ├── database
    │       │   ├── config.py
    │       │   ├── models.py
    │       │   └── register.py
    │       ├── main.py
    │       └── schemas
    │           ├── notes.py
    │           └── users.py
    └── frontend
        ├── .gitignore
        ├── Dockerfile
        ├── README.md
        ├── babel.config.js
        ├── jsconfig.json
        ├── package-lock.json
        ├── package.json
        ├── public
        │   ├── favicon.ico
        │   └── index.html
        ├── src
        │   ├── App.vue
        │   ├── assets
        │   │   └── logo.png
        │   ├── components
        │   │   └── HelloWorld.vue
        │   ├── main.js
        │   ├── router
        │   │   └── index.js
        │   └── views
        │       ├── AboutView.vue
        │       └── HomeView.vue
        └── vue.config.js
```

这是一个很好的停下来的时间点，回顾一下你到目前为止所完成的工作，并将 pytest 与 CRUD 辅助函数连接起来进行测试。如果需要帮助，请查看《使用 FastAPI 和 Pytest 开发和测试异步 API》。