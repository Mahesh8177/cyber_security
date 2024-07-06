from flask import Flask, request, jsonify, render_template
from cyber.utils import AnomolyDetection
import config

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('performance.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.form
    required_fields = [
        'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'logged_in', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_srv_rerror_rate'
    ]
    
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing data'}), 400

    attack = AnomolyDetection(
        protocol_type=data['protocol_type'],
        service=data['service'],
        flag=data['flag'],
        src_bytes=float(data['src_bytes']),
        dst_bytes=float(data['dst_bytes']),
        logged_in=int(data['logged_in']),
        count=int(data['count']),
        srv_count=int(data['srv_count']),
        serror_rate=float(data['serror_rate']),
        srv_serror_rate=float(data['srv_serror_rate']),
        rerror_rate=float(data['rerror_rate']),
        srv_rerror_rate=float(data['srv_rerror_rate']),
        same_srv_rate=float(data['same_srv_rate']),
        diff_srv_rate=float(data['diff_srv_rate']),
        dst_host_count=int(data['dst_host_count']),
        dst_host_srv_count=int(data['dst_host_srv_count']),
        dst_host_same_srv_rate=float(data['dst_host_same_srv_rate']),
        dst_host_diff_srv_rate=float(data['dst_host_diff_srv_rate']),
        dst_host_srv_diff_host_rate=float(data['dst_host_srv_diff_host_rate']),
        dst_host_serror_rate=float(data['dst_host_serror_rate']),
        dst_host_srv_serror_rate=float(data['dst_host_srv_serror_rate']),
        dst_host_srv_rerror_rate=float(data['dst_host_srv_rerror_rate'])
    )
    
    prediction = attack.get_anomaly_prediction()
    
    return render_template('performance.html', prediction=prediction)

if __name__ == '__main__':
    app.run(debug=True)
