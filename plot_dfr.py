import matplotlib.pyplot as plt

def read_dfr_file(fname):
    retx = []
    rety = []
    with open(fname, 'r') as f:
        for line in f:
            rx, ry = line.split(',')
            retx.append(int(rx))
            rety.append(int(ry))
    return retx, rety



if __name__ == '__main__':
    x, y = read_dfr_file("dfr.txt")
    plt.plot(x, y)
    plt.show()