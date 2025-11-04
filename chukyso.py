from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from PyPDF2 import PdfReader, PdfWriter
from datetime import datetime
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
import os

# ===================== CẤU HÌNH =====================
PDF_INPUT = "chukiso.pdf"               # file PDF gốc
PDF_TEMP = "chukiso_temp.pdf"           # file tạm có ảnh chữ ký
PDF_OUTPUT = "signed_output.pdf"        # file đầu ra đã ký
SIGN_IMAGE = "signature.png"            # ảnh chữ ký tay (PNG)
PRIVATE_KEY = "mykey.pem"               # khóa riêng tư
CERT_FILE = "mycert.pem"                # chứng chỉ
NAME = "Phạm Khắc Linh"
PHONE = "0911417710"
FONT_FILE = r"C:\Windows\Fonts\times.ttf"  # font Times New Roman gốc Windows
FONT_NAME = "TimesNewRoman"

# ===================== ĐĂNG KÝ FONT =====================
pdfmetrics.registerFont(TTFont(FONT_NAME, FONT_FILE))

# ===================== BƯỚC 1: CHÈN ẢNH + THÔNG TIN =====================
c = canvas.Canvas("overlay.pdf", pagesize=A4)

# Vị trí ảnh chữ ký (góc phải dưới)
img_x = 350
img_y = 400
img_w = 150
img_h = 70

c.drawImage(SIGN_IMAGE, img_x, img_y, width=img_w, height=img_h)
c.setFont(FONT_NAME, 10)

# Thông tin người ký
text_x = img_x
text_y = img_y - 15
c.drawString(text_x, text_y, f"Người ký: {NAME}")
c.drawString(text_x, text_y - 12, f"SĐT: {PHONE}")
c.drawString(text_x, text_y - 24, f"Ngày ký: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
c.save()

print("✅ Đã chèn ảnh chữ ký và thông tin vào overlay.pdf")

# ===================== BƯỚC 2: GHÉP OVERLAY VÀO PDF GỐC =====================
reader = PdfReader(PDF_INPUT)
writer = PdfWriter()
overlay = PdfReader("overlay.pdf")

overlay_page = overlay.pages[0]
for page in reader.pages:
    page.merge_page(overlay_page)
    writer.add_page(page)

with open(PDF_TEMP, "wb") as f_out:
    writer.write(f_out)

print("✅ Đã gộp overlay vào file PDF tạm:", PDF_TEMP)

# ===================== BƯỚC 3: KÝ SỐ =====================
signer = signers.SimpleSigner.load(
    key_file=PRIVATE_KEY,
    cert_file=CERT_FILE,
    key_passphrase=b"123456"  # mật khẩu PEM
)

meta = PdfSignatureMetadata(
    field_name="Signature1",
    reason="Phê duyệt báo cáo nhân sự",
    location="Đại học Kỹ thuật Công nghiệp - TNUT"
)

with open(PDF_TEMP, "rb") as pdf_in, open(PDF_OUTPUT, "wb") as pdf_out:
    pdf_writer = IncrementalPdfFileWriter(pdf_in)
    pdf_signer = signers.PdfSigner(
        signature_meta=meta,
        signer=signer,
        new_field_spec=SigFieldSpec(sig_field_name="Signature1")
    )
    pdf_signer.sign_pdf(pdf_writer, output=pdf_out)

print("✅ Đã ký số thành công! File đầu ra:", PDF_OUTPUT)

# ===================== DỌN DẸP FILE TẠM =====================
os.remove("overlay.pdf")
os.remove(PDF_TEMP)

print("🎉 Hoàn tất! File PDF đã ký số có ảnh chữ ký thật:", PDF_OUTPUT)