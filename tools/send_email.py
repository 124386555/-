"""
Mock工具：send_email
记录发送信息但不真实发送，标记为高危工具
"""
from typing import Type
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


class SendEmailInput(BaseModel):
    to: str = Field(description="收件人邮箱地址")
    subject: str = Field(description="邮件主题")
    body: str = Field(description="邮件正文内容")


class SendEmailTool(BaseTool):
    name: str = "send_email"
    description: str = "发送电子邮件给指定收件人。这是高危操作，需要人工确认。"
    args_schema: Type[BaseModel] = SendEmailInput

    def _run(self, to: str, subject: str, body: str) -> dict:
        """执行邮件发送（Mock，仅记录）"""
        # 记录发送信息，不真实发送
        record = {
            "to": to,
            "subject": subject,
            "body": body,
            "sent": False,
            "note": "[Mock] 邮件未真实发送，仅记录",
        }

        return {
            "status": "ok",
            "data": f"[Mock] 邮件已记录 -> 收件人: {to}, 主题: {subject}",
            "metadata": record,
        }
