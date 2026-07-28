"""
Mock工具：file_write
模拟文件写入，记录写入路径和内容但不真实写入磁盘
维护内存中的虚拟文件系统状态，用于测试写入权限控制
"""
from typing import Type
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


# 内存虚拟文件系统（记录所有写入操作）
_virtual_fs: dict[str, str] = {}

# 敏感路径模式（用于审计标记）
SENSITIVE_PATHS = [
    "/etc/", "/root/", "/var/log/", "shadow", "passwd",
    ".env", "config.yaml", "credentials",
]


class FileWriteInput(BaseModel):
    file_path: str = Field(description="写入文件的路径")
    content: str = Field(description="要写入的文件内容")


class FileWriteTool(BaseTool):
    name: str = "file_write"
    description: str = "将内容写入指定路径的文件。这是写操作，需要write权限。"
    args_schema: Type[BaseModel] = FileWriteInput

    def _run(self, file_path: str, content: str) -> dict:
        """执行文件写入（Mock，仅记录不真实写入）"""
        # 记录到虚拟文件系统
        _virtual_fs[file_path] = content

        # 标记是否为敏感路径
        is_sensitive = any(sp in file_path.lower() for sp in SENSITIVE_PATHS)

        return {
            "status": "ok",
            "data": f"[Mock] 文件写入已记录 -> 路径: {file_path}, 大小: {len(content)}字节",
            "metadata": {
                "file_path": file_path,
                "content_length": len(content),
                "is_sensitive_path": is_sensitive,
                "mock": True,
                "note": "[Mock] 文件未真实写入磁盘，仅记录到内存",
            },
        }
