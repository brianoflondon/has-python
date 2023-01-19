from PIL import ImageDraw, ImageFont
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_H
from qrcode.image.styledpil import StyledPilImage
import requests


async def get_qrcode(qr_text: str, text: str) -> StyledPilImage:
    """
    Returns a QR Image
    """

    qr = QRCode(
        version=1,
        error_correction=ERROR_CORRECT_H,
        box_size=10,
        border=6,
    )
    qr.add_data(qr_text)
    Create a new image with a white background
    text = str(
        f"Check: {self.auth_wait.uuid} - "
        f"{self.hive_acc} - {self.key_type.value}"
    )
    res = requests.get(f"https://api.v4v.app/v1/hive/avatar/{self.hive_acc}")
    if res.status_code == 200:
        # avatar_im = Image.open(BytesIO(res.content))
        with open(f"/tmp/{self.hive_acc}.png", "wb") as file:
            file.write(res.content)

        img = qr.make_image(
            image_factory=StyledPilImage,
            embeded_image_path=f"/tmp/{self.hive_acc}.png",
        )
    else:
        img = qr.make_image()
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype("src/has_python/arial_narrow_bold_italic.ttf", 24)
    draw.text((100, 10), text, font=font, fill="black")
    return img