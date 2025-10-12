import re

# اسم الملف الأصلي
input_file = "applicant-register.html"       # غيّر الاسم لملفك
output_file = "file.clean.html"

# أحرف Unicode التي تسبب مشاكل
pattern = re.compile(r'[\u00A0\u200B-\u200F\u202A-\u202E\uFEFF\u200C\u200D]')

# اقرأ الملف
with open(input_file, 'r', encoding='utf-8') as f:
    text = f.read()

# إزالة الأحرف الغريبة
clean_text = pattern.sub('', text)

# احفظ الملف المنظف
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(clean_text)

print(f"تم التنظيف! الملف الجديد: {output_file}")
