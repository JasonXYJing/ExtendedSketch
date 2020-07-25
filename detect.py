from __future__ import print_function
import pandas as pd
import os
import datetime
try:
    from reprlib import repr
except ImportError:
    pass


class Experiment:
    def __init__(self, file_path):
        self.file_path = file_path
        self.ExtendedSketch = None
        self.count = 0
        self.throughput = 0
        self.spreader_detect = []
        self.changer_detect = []
        self.src_list = []
        self.spreader_real = None
        self.changer_real = None
        self.precision_spreader = None
        self.precision_Changer = None
        self.recall_spreader = None
        self.recall_Changer = None
        self.AREDC = 0
        self.host_threshold = 379

    def step1(self):
        files = os.listdir(self.file_path)
        file_num = 1
        for file in files:
            self.count += 1
            self.ExtendedSketch.initialize()

            f = os.path.join(self.file_path, file)
            df = pd.read_csv(f, usecols=['Src IP', 'Dst IP'])
            table = df.drop_duplicates().reset_index(drop=True)
            self.ExtendedSketch.process_data(table, 0, len(table))
            sp_abrow_list, sc_abrow_list = self.ExtendedSketch.sp_detection()
            sip_list_spreader = self.ExtendedSketch.recon_sip(sp_abrow_list)
            self.spreader_detect.extend(sip_list_spreader)
            if sc_abrow_list:
                sip_list_changer = self.ExtendedSketch.recon_sip(sc_abrow_list)

            else:
                sip_list_changer = []
            self.changer_detect.extend(sip_list_changer)
            src_des = table.groupby('Src IP')['Dst IP'].nunique()
            self.src_list.extend(src_des.index)
            dc_aresum = 0
            host_num = 0
            for item in src_des.index:
                real_dc = src_des[item]
                if real_dc > self.host_threshold:
                    est_dc = self.ExtendedSketch.estimation_operation(item)
                    dc_aresum += float(abs(est_dc - real_dc)) / real_dc
                    host_num += 1
            ARE_dc = float(dc_aresum) / host_num
            self.AREDC += ARE_dc
            file_num += 1

    def step2(self):
        self.spreader_detect = set(self.spreader_detect)
        self.changer_detect = set(self.changer_detect)
        true_spreader_detect = set(self.spreader_detect) & set(self.spreader_real)
        self.precision_spreader= float(len(true_spreader_detect)/len(self.spreader_detect))
        self.recall_spreader = float(len(true_spreader_detect)/len(self.spreader_real))
        true_changer_detect = set(self.changer_detect) & set(self.changer_real)
        self.precision_changer = float(len(true_changer_detect) / len(self.changer_detect))
        self.recall_changer = float(len(true_changer_detect) / len(self.changer_real))
        print('Pre_Spreader为:{:%}'.format(self.precision_spreader))
        print('Rec_Spreader为:{:%}'.format(self.recall_spreader))
        print('Pre_Changer为:{:%}'.format(self.precision_changer))
        print('Rec_Changer为:{:%}'.format(self.recall_changer))
        self.AREDC = self.AREDC / self.count
        print('AREDC为：{:.3f}'.format(self.AREDC))

