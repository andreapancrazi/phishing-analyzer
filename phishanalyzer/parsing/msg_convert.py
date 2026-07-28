"""Convert Outlook .msg files into RFC-5322 bytes so they can flow through
the same EmailAnalyzer pipeline as a normal .eml — no parallel parser.

Requires the `extract-msg` package.
"""

from email.message import EmailMessage
from email.utils import format_datetime

try:
    import extract_msg
    HAS_EXTRACT_MSG = True
except ImportError:
    HAS_EXTRACT_MSG = False


class MsgConversionError(Exception):
    pass


def msg_to_eml_bytes(path):
    """Returns (raw_bytes, reconstructed: bool).

    reconstructed=True means the original .msg had no preserved transport
    headers, so the header block (and therefore Authentication/Transmission
    data) was synthesized from the message's basic fields rather than
    recovered verbatim.
    """
    if not HAS_EXTRACT_MSG:
        raise MsgConversionError(
            "The 'extract-msg' package is required to open .msg files. "
            "Install it with: pip install extract-msg"
        )

    msg = extract_msg.openMsg(path)
    try:
        # `headerText` is the raw header stream — present only when Outlook
        # preserved the original transport headers. `header` always returns a
        # parsed email.message.Message, synthesizing one from From/To/Cc/Date/
        # Message-Id when headerText is absent.
        reconstructed = not msg.headerText
        parsed_header = msg.header

        eml = EmailMessage()
        for name, value in parsed_header.items():
            if value is None or name.lower() in ("content-type", "mime-version"):
                continue
            try:
                eml[name] = str(value)
            except Exception:
                pass

        if "From" not in eml and msg.sender:
            eml["From"] = msg.sender
        if "To" not in eml and msg.to:
            eml["To"] = msg.to
        if msg.cc and "Cc" not in eml:
            eml["Cc"] = msg.cc
        if "Subject" not in eml:
            eml["Subject"] = msg.subject or ""
        if "Date" not in eml:
            try:
                if msg.date:
                    eml["Date"] = format_datetime(msg.date)
            except Exception:
                pass
        if "Message-ID" not in eml and getattr(msg, "messageId", None):
            eml["Message-ID"] = msg.messageId

        plain_body = msg.body or ""
        html_body = msg.htmlBody
        if isinstance(html_body, bytes):
            html_body = html_body.decode("utf-8", errors="replace")

        eml.set_content(plain_body or " ")
        if html_body:
            eml.add_alternative(html_body, subtype="html")

        for att in getattr(msg, "attachments", []) or []:
            data = att.data
            if not data:
                continue
            filename = att.longFilename or att.shortFilename or "unnamed"
            eml.add_attachment(data, maintype="application", subtype="octet-stream",
                                filename=filename)

        return eml.as_bytes(), reconstructed
    finally:
        try:
            msg.close()
        except Exception:
            pass
