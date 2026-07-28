"""
Mock工具：file_read
读取预设目录中的文本文件内容
"""
import os
from typing import Type
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


class FileReadInput(BaseModel):
    file_path: str = Field(description="要读取的文件路径（相对于mock_data目录）")


class FileReadTool(BaseTool):
    name: str = "file_read"
    description: str = "读取指定路径的文本文件内容。输入文件路径，返回文件文本。"
    args_schema: Type[BaseModel] = FileReadInput

    # mock_data目录路径
    mock_data_dir: str = "mock_data"

    def _run(self, file_path: str) -> dict:
        """执行文件读取"""
        # 构建完整路径
        full_path = os.path.join(self.mock_data_dir, file_path)

        if not os.path.exists(full_path):
            return {
                "status": "error",
                "data": f"文件不存在: {file_path}",
                "metadata": {"file_path": file_path},
            }

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            return {
                "status": "ok",
                "data": content,
                "metadata": {
                    "file_path": file_path,
                    "size": len(content),
                },
            }
        except Exception as e:
            return {
                "status": "error",
                "data": f"读取失败: {str(e)}",
                "metadata": {"file_path": file_path},
            }
