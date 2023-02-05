import matplotlib.pyplot as plt

def read_dist_file(fname):
    retx = []
    rety = []
    with open(fname, 'r') as f:
        for line in f:
            rx, ry = line.split(',')
            retx.append(int(rx))
            rety.append(int(ry))
    return retx, rety



if __name__ == '__main__':
    h0_x, h0_y = read_dist_file("distances_h0.txt")
    plt.bar(h0_x, h0_y)
    plt.show()
    h1_x, h1_y = read_dist_file("distances_h1.txt")
    plt.bar(h1_x, h1_y)
    plt.show()
    h_x, h_y = read_dist_file("distances_h.txt")
    plt.bar(h_x, h_y)
    plt.show()