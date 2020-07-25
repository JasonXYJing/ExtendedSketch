from __future__ import print_function
from functools import reduce
import math
import datetime
import sys
import numpy as np
from collections import Counter
from sys import getsizeof, stderr
from itertools import chain
from collections import deque
try:
    from reprlib import repr
except ImportError:
    pass


def egcd(a, b):
    if 0 == b:
        return 1, 0, a
    x, y, q = egcd(b, a % b)
    x, y = y, (x - a // b * y)
    return x, y, q

def chinese_remainder(mod_list, remainder_list):
    mod_product = reduce(lambda x, y: x * y, mod_list)
    mi_list = [mod_product // x for x in mod_list]
    mi_inverse = [egcd(mi_list[i], mod_list[i])[0] for i in range(len(mi_list))]
    x = 0
    for i in range(len(remainder_list)):
        x += mi_list[i] * mi_inverse[i] * remainder_list[i]
        x %= mod_product
    return x

def addr2dec(addr):
    items = [int(x) for x in addr.split(".")]
    return sum([items[i] << [24, 16, 8, 0][i] for i in range(4)])

def dec2addr(dec):
    return ".".join([str(dec >> x & 0xff) for x in [24, 16, 8, 0]])


class ExtendedSketch:
    def __init__(self, h, p, w):
        self.w = w
        self.p = p
        self.h = h
        self.cw_threshold = 0.75
        self.correct = math.log(pow(2-self.cw_threshold, 2) / (4*(1-self.cw_threshold)))
        self.sp_threshold = 379
        self.changer_threshold = 193
        self.ExtendedSketch = None
        self.additional_info = None
        self.pre_changer = None

    def generate_ExtendedSketch(self):
        self.ExtendedSketch = []
        self.additional_info = []
        for i in range(self.h):
            a = [[0] * self.w for column_num in range(self.p[i])]
            b = [[0, 0, []] for column_num in range(self.p[i])]
            self.ExtendedSketch.append(a)
            self.additional_info.append(b)

    def initialize(self):
        self.generate_ExtendedSketch()

    def process_data(self, table, low_rows, up_rows):
        for i in range(low_rows, up_rows):
            source = table.loc[i, 'Src IP']
            destination = table.loc[i, 'Dst IP']
            self.update(source, destination)

    def check_extension_status(self, src):
        cw = 0
        for x in range(self.h):
            if self.additional_info[x][src % self.p[x]][0] >= self.cw_threshold:
                cw += 1
        if cw == self.h:
            status = True
        else:
            status = False
        return status

    def update(self, source, destination):
        src = addr2dec(source)
        des = addr2dec(destination)
        extension_status = self.check_extension_status(src)
        if extension_status:
            for array_num in range(self.h):
                column = int(src % self.p[array_num])
                self.ExtendedSketch[array_num][column] = self.column_extension(self.ExtendedSketch[array_num][column], array_num)
                column_length = len(self.ExtendedSketch[array_num][column])
                row = int((src+des) % column_length)
                self.ExtendedSketch[array_num][column][row] = 1
                self.additional_info[array_num][column][0] = self.ExtendedSketch[array_num][column].count(1) / column_length
                self.additional_info[array_num][column][1] += 1
                try:
                    self.additional_info[array_num][column][2].append(int(src % self.p[array_num + 1]))
                except:
                    continue
        else:
            for array_num in range(self.h):
                column = int(src % self.p[array_num])
                column_length = len(self.ExtendedSketch[array_num][column])
                row = int((src+des) % column_length)
                self.ExtendedSketch[array_num][column][row] = 1
                self.additional_info[array_num][column][0] = self.ExtendedSketch[array_num][column].count(1) / column_length
                try:
                    self.additional_info[array_num][column][2].append(int(src % self.p[array_num + 1]))
                except:
                    continue

    def column_extension(self, column, array_num):
        old_length = len(column)
        new_column = [0] * (2 * old_length)
        bit_location = [i for i, x in enumerate(column) if x == 1]

        if array_num % 2 != 0:
            for location in bit_location:
                new_column[location] = 1
        else:
            for location in bit_location:
                new_column[location+old_length] = 1
        return new_column

    def estimation_operation(self, source):
        src = addr2dec(source)

        if self.additional_info[0][src % self.p[0]][1] == 0:
            estimation_result = self.estimation_no_extension(src)
        else:
            estimation_result = self.estimation_extension(src)
        return estimation_result

    def estimation_no_extension(self, src):
        esi = []
        for i in range(self.h):
            column = int(src % self.p[i])
            esi.append(self.ExtendedSketch[i][column])
        es = []
        for i in range(self.w):
            es.append(esi[0][i] & esi[1][i] & esi[2][i] & esi[3][i])  # h = 4
        zero_num = Counter(es)[0]
        if zero_num != 0:
            dc = round((-self.w) * math.log(zero_num / self.w))
        else:
            dc = round((-self.w) * math.log(1 / self.w))
        return dc

    def estimation_extension(self, src):
        dc_list = []
        for i in range(self.h):
            column = src % self.p[i]
            dc = self.cal_dc(i, column)
            dc_list.append(dc)
        min_dc = min(dc_list)
        return min_dc

    def cal_dc(self, i, column):
        zero_num = self.ExtendedSketch[i][column].count(0)
        column_length = len(self.ExtendedSketch[i][column])
        if zero_num != 0:
            dc = round((-column_length) * math.log(zero_num / column_length))
        else:
            dc = round((-column_length) * math.log(1 / column_length))
        sum_extension = sum([pow(2, i) for i in range(self.additional_info[i][column][1])])
        correct_item = self.correct * self.w * sum_extension
        return dc + correct_item

    def sp_detection(self):
        abrow_list_spreader = []
        abrow_list_changer = []
        new_row_changer = []
        if self.pre_changer is None:
            for array_num in range(self.h):
                sub_abnormal_spreader = []
                new_row_changer.append({})
                for column_num in range(self.p[array_num]):
                    if self.additional_info[array_num][column_num][1] != 0:
                        dc = self.cal_dc(array_num, column_num)
                        new_row_changer[array_num][column_num] = dc
                        if dc >= self.sp_threshold:
                            sub_abnormal_spreader.append(column_num)
                abrow_list_spreader.append(sub_abnormal_spreader)
        else:
            for array_num in range(self.h):
                sub_abnormal_spreader = []
                sub_abnormal_changer = []
                new_row_changer.append({})
                for column_num in range(self.p[array_num]):
                    if self.additional_info[array_num][column_num][1] != 0:
                        dc = self.cal_dc(array_num, column_num)
                        new_row_changer[array_num][column_num] = dc

                        if dc >= self.sp_threshold:
                            sub_abnormal_spreader.append(column_num)

                        if column_num not in self.pre_changer[array_num]:
                            if dc >= self.changer_threshold:
                                sub_abnormal_changer.append(column_num)
                        else:
                            change_column = max(0, dc - self.pre_changer[array_num][column_num])
                            if change_column >= self.changer_threshold:
                                sub_abnormal_changer.append(column_num)
                abrow_list_spreader.append(sub_abnormal_spreader)
                abrow_list_changer.append(sub_abnormal_changer)
        self.pre_changer = new_row_changer
        return abrow_list_spreader, abrow_list_changer

    def recon_sip(self, abrow_list, cur=0, num_list=None, sip_list=None, column_num=None):
        if cur == 0:
            sip_list = []
            for num in abrow_list[0]:
                original_list = [num]
                for flag in set(self.additional_info[cur][num][2]):
                    if flag in abrow_list[1]:
                        num_list = original_list.copy()
                        num_list.append(flag)
                        columnnum = flag
                        self.recon_sip(abrow_list, cur + 1, num_list, sip_list, columnnum)
                    else:
                        continue
            return sip_list
        elif cur == self.h - 1:
            ipaddress = dec2addr(chinese_remainder(self.p, num_list))
            sip_list.append(ipaddress)
        else:
            original_list = num_list.copy()
            for flag in set(self.additional_info[cur][column_num][2]):
                if flag in abrow_list[cur + 1]:
                    num_list = original_list.copy()
                    num_list.append(flag)
                    columnnum = flag
                    self.recon_sip(abrow_list, cur + 1, num_list, sip_list, columnnum)
                else:
                    continue