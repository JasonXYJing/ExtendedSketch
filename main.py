from detect import *
from extendedsketch import *
from superhost import *


def test(h, p, w):
    es = ExtendedSketch(h, p, w)
    filename = 'caida1'        # CSV format file
    super_host_name = filename  # superhost library contains two dictionary, one stores super spreader and another stores super changers.
    experiment = Experiment(filename)
    experiment.ExtendedSketch = es

    experiment.spreader_real = spreader[super_host_name]   # true super spreaders
    experiment.changer_real = changer[super_host_name]     # true super changers
    experiment.step1()
    experiment.step2()


test(4, [45007, 45013, 45053, 45061], 32)


