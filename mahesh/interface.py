from flask import Flask, render_template, request, jsonify
from cyber.utils import Anomoly_detection
import config

app = Flask(__name__)

#################################################################################################################
#################################### Home Page API ##############################################################
#################################################################################################################

@app.route('/')
def performance_model():
    print('Welcome to Cyber Security model')
    return render_template('performance.html')

###################################################################################################################
########################################## Model API ##############################################################
###################################################################################################################

@app.route('/anomalies_Detection', methods=['POST', 'GET'])
def get_anomaly_prediction():
    if request.method == 'POST':
        print('We are in the POST method')
        data = request.form
        protocol_type = data['protocol_type']
        service = data['service']
        flag = data['flag']
        src_bytes = float(data['src_bytes'])
        dst_bytes = float(data['dst_bytes'])
        logged_in = float(data['logged_in'])
        count = float(data['count'])
        srv_count = float(data['srv_count'])
        serror_rate = float(data['serror_rate'])
        srv_serror_rate = float(data['srv_serror_rate'])
        rerror_rate = float(data['rerror_rate'])
        srv_rerror_rate = float(data['srv_rerror_rate'])
        same_srv_rate = float(data['same_srv_rate'])
        diff_srv_rate = float(data['diff_srv_rate'])
        dst_host_count = float(data['dst_host_count'])
        dst_host_srv_count = float(data['dst_host_srv_count'])
        dst_host_same_srv_rate = float(data['dst_host_same_srv_rate'])
        dst_host_diff_srv_rate = float(data['dst_host_diff_srv_rate'])
        dst_host_srv_diff_host_rate = float(data['dst_host_srv_diff_host_rate'])
        dst_host_serror_rate = float(data['dst_host_serror_rate'])
        dst_host_srv_serror_rate = float(data['dst_host_srv_serror_rate'])
        dst_host_srv_rerror_rate = float(data['dst_host_srv_rerror_rate'])

        prediction = Anomoly_detection(protocol_type, service, flag, src_bytes, dst_bytes,
                                       logged_in, count, srv_count, serror_rate, srv_serror_rate,
                                       rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate,
                                       dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
                                       dst_host_diff_srv_rate, dst_host_srv_diff_host_rate,
                                       dst_host_serror_rate, dst_host_srv_serror_rate,
                                       dst_host_srv_rerror_rate)
        
        cyber_prediction = prediction.get_anamoly_prediction()

        return jsonify({'the cyber security prediction is': int(cyber_prediction)})
    
    else:
        print('We are in the GET method')
        data1 = request.args
        protocol_type = data1.get('protocol_type')
        service = data1.get('service')
        flag = data1.get('flag')
        src_bytes = float(data1.get('src_bytes'))
        dst_bytes = float(data1.get('dst_bytes'))
        logged_in = float(data1.get('logged_in'))
        count = float(data1.get('count'))
        srv_count = float(data1.get('srv_count'))
        serror_rate = float(data1.get('serror_rate'))
        srv_serror_rate = float(data1.get('srv_serror_rate'))
        rerror_rate = float(data1.get('rerror_rate'))
        srv_rerror_rate = float(data1.get('srv_rerror_rate'))
        same_srv_rate = float(data1.get('same_srv_rate'))
        diff_srv_rate = float(data1.get('diff_srv_rate'))
        dst_host_count = float(data1.get('dst_host_count'))
        dst_host_srv_count = float(data1.get('dst_host_srv_count'))
        dst_host_same_srv_rate = float(data1.get('dst_host_same_srv_rate'))
        dst_host_diff_srv_rate = float(data1.get('dst_host_diff_srv_rate'))
        dst_host_srv_diff_host_rate = float(data1.get('dst_host_srv_diff_host_rate'))
        dst_host_serror_rate = float(data1.get('dst_host_serror_rate'))
        dst_host_srv_serror_rate = float(data1.get('dst_host_srv_serror_rate'))
        dst_host_srv_rerror_rate = float(data1.get('dst_host_srv_rerror_rate'))

        prediction1 = Anomoly_detection(protocol_type, service, flag, src_bytes, dst_bytes,
                                        logged_in, count, srv_count, serror_rate, srv_serror_rate,
                                        rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate,
                                        dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
                                        dst_host_diff_srv_rate, dst_host_srv_diff_host_rate,
                                        dst_host_serror_rate, dst_host_srv_serror_rate,
                                        dst_host_srv_rerror_rate)
        cyber_prediction1 = prediction1.get_anamoly_prediction()
        return jsonify({'the cyber security prediction is': int(cyber_prediction1)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config.PORT_NUMBER, debug=True)
