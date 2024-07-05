import pickle
import json
import config
import numpy as np

class anomoly_detection():
    def __init__(self,protocol_type,service,flag,src_bytes,dst_bytes,
                 logged_in,count,srv_count,serror_rate,srv_serror_rate,
                 rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,
                 dst_host_count,dst_host_srv_count,dst_host_same_srv_rate,
                 dst_host_diff_srv_rate,dst_host_srv_diff_host_rate,
                 dst_host_serror_rate,dst_host_srv_serror_rate,
                 dst_host_srv_rerror_rate):
        self.protocol_type= protocol_type
        self.service= service
        self.flag=flag
        self.src_bytes=src_bytes
        self.dst_bytes=dst_bytes
        self.logged_in=logged_in
        self.count=count
        self.srv_count=srv_count
        self.serror_rate=serror_rate
        self.srv_serror_rate=srv_serror_rate
        self.rerror_rate=rerror_rate
        self.srv_rerror_rate=srv_rerror_rate
        self.same_srv_rate=same_srv_rate
        self.diff_srv_rate=diff_srv_rate
        self.dst_host_count=dst_host_count
        self.dst_host_srv_count=dst_host_srv_count
        self.dst_host_same_srv_rate=dst_host_same_srv_rate
        self.dst_host_diff_srv_rate=dst_host_diff_srv_rate
        self.dst_host_srv_diff_host_rate=dst_host_srv_diff_host_rate
        self.dst_host_serror_rate=dst_host_serror_rate
        self.dst_host_srv_serror_rate=dst_host_srv_serror_rate
        self.dst_host_srv_rerror_rate=dst_host_srv_rerror_rate

    def load_model(self):
        with open(config.model_path,'rb') as f:
            self.model=pickle.load(f)

        with open(config.json_path, 'r') as f:
            self.project_data=json.load(f)
    def get_anamoly_prediction(self):
        self.load_model()

        test_array = np.zeros(22)
        test_array[0]=self.project_data['protocol_type'][self.protocol_type]
        test_array[1]=self.project_data['service'][self.service]
        test_array[2]=self.project_data['flag'][self.flag]
        test_array[3]=self.src_bytes
        test_array[4]=self.dst_bytes
        test_array[5]=self.logged_in
        test_array[6]=self.count
        test_array[7]=self.srv_count
        test_array[8]=self.serror_rate
        test_array[9]=self.srv_serror_rate
        test_array[10]=self.rerror_rate
        test_array[11]=self.srv_rerror_rate
        test_array[12]=self.same_srv_rate
        test_array[13]=self.diff_srv_rate
        test_array[14]=self.dst_host_count
        test_array[15]=self.dst_host_srv_count
        test_array[16]=self.dst_host_same_srv_rate
        test_array[17]=self.dst_host_diff_srv_rate
        test_array[18]=self.dst_host_srv_diff_host_rate
        test_array[19]=self.dst_host_serror_rate
        test_array[20]=self.dst_host_srv_serror_rate
        test_array[21]=self.dst_host_srv_rerror_rate
        print('the Test array is',test_array)

        prediction = self.model.predict([test_array])[0]
        print(f'The Prediction Of Attack is ', prediction)
        return prediction

if __name__=='__main__':
 protocol_type= 'icmp'
 service= 'auth'
 flag= 'RSTO'
 src_bytes=145
 dst_bytes=143
 logged_in=1
 count=15
 srv_count=0
 serror_rate=1
 srv_serror_rate=1
 rerror_rate=0.06
 srv_rerror_rate=1.00
 same_srv_rate=0.06
 diff_srv_rate=0.87
 dst_host_count=67
 dst_host_srv_count=90
 dst_host_same_srv_rate=0.14
 dst_host_diff_srv_rate=0.170
 dst_host_srv_diff_host_rate=0.40
 dst_host_serror_rate=0.20
 dst_host_srv_serror_rate=0
 dst_host_srv_rerror_rate=0.10
 cyber_goal= anomoly_detection(protocol_type,service,flag,src_bytes,dst_bytes,
                 logged_in,count,srv_count,serror_rate,srv_serror_rate,
                 rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,
                 dst_host_count,dst_host_srv_count,dst_host_same_srv_rate,
                 dst_host_diff_srv_rate,dst_host_srv_diff_host_rate,
                 dst_host_serror_rate,dst_host_srv_serror_rate,
                 dst_host_srv_rerror_rate)
cyber_goal.get_anamoly_prediction()