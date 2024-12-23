import torch
from flask import Flask, request, jsonify
from transformers import MBartForConditionalGeneration, MBart50Tokenizer

# Khởi tạo ứng dụng Flask
app = Flask(__name__)

# Tải mô hình và tokenizer
model_name = 'facebook/mbart-large-50-many-to-many-mmt'
tokenizer = MBart50Tokenizer.from_pretrained(model_name)
model = MBartForConditionalGeneration.from_pretrained(model_name)

# Hàm để dịch văn bản từ tiếng Nhật sang tiếng Anh
def translate_text(text, max_length=None):
    source_lang = "ja_XX"  # Mã ngôn ngữ tiếng Nhật
    input_ids = tokenizer.encode(source_lang + ' ' + text, return_tensors='pt', padding=True, truncation=True)

    # Tạo bản dịch
    if max_length is None:
        translated = model.generate(input_ids)
    else:
        translated = model.generate(input_ids, max_length=max_length)
    
    translation = tokenizer.decode(translated[0], skip_special_tokens=True)
    return translation

# API endpoint cho dịch thuật
@app.route('/translate', methods=['POST'])
def translate():
    data = request.json
    text = data.get('text')
    max_length = data.get('max_length', None)  # Độ dài tối đa tùy chọn

    if text is None:
        return jsonify({'error': 'Text is required'}), 400
    
    translation = translate_text(text, max_length)
    return jsonify({'translation': translation})

# Chạy ứng dụng Flask
if __name__ == '__main__':
    app.run(debug=True)