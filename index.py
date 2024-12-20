from flask import Flask, request, jsonify
from transformers import MarianMTModel, MarianTokenizer
import threading

app = Flask(__name__)

# Tải mô hình và tokenizer MarianMT
model_name = 'Helsinki-NLP/opus-mt-ja-en'  # Mô hình dịch từ tiếng Nhật sang tiếng Anh
tokenizer = MarianTokenizer.from_pretrained(model_name)
model = MarianMTModel.from_pretrained(model_name)

# Hàm để xử lý dịch thuật trong một luồng riêng
def translate_text(text, result_dict, request_id):
    inputs = tokenizer(text, return_tensors='pt', padding=True, truncation=True)
    translated = model.generate(**inputs, max_length=50)
    translation = tokenizer.decode(translated[0], skip_special_tokens=True)
    result_dict[request_id] = translation

@app.route('/translate', methods=['POST'])
def translate():
    data = request.get_json()
    text = data.get('text', '')
    request_id = str(id(data))  # Tạo ID yêu cầu duy nhất

    # Tạo dictionary để lưu kết quả
    result_dict = {}

    # Tạo và bắt đầu luồng
    translate_thread = threading.Thread(target=translate_text, args=(text, result_dict, request_id))
    translate_thread.start()
    translate_thread.join()  # Chờ luồng hoàn tất

    # Trả về kết quả
    return jsonify({'translation': result_dict[request_id]})

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
