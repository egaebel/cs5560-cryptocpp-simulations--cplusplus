import sys

x_leg_pos = "0.75"
y_leg_pos = "-0.17"

ESDH = "Ephemeral Diffie-Hellman" 
ECDH = "Elliptic Curve Diffie-Hellman"
ECMQV = "Elliptic Curve Menezes-Qu-Vanstone"
STATIC_KEY = "Static Key"
AES = "AES" 
BLOWFISH = "Blowfish"
SALSA = "Salsa20" 
SOSE = "Sosemanuk"
HMAC = "HMAC"
CMAC = "CMAC"
VMAC = "VMAC"

PLOT_MARKS = ["*", "x ", "+", "|", "o", "asterisk", "star", "10-pointed star",
                "oplus", "oplus*", "otimes", "otimes*", "square", "square*", 
                "triangle", "triangle*", "diamond", "halfdiamond*", 
                "halfsquare*", "right*", "left*", "Mercedes star", 
                "Mercedes star flipped", "halfcircle", "halfcircle*", 
                "pentagon", "pentagon*", "cubes"]

PLOT_COLORS = ["blue", "red", "green", "brown", "pink", "purple", "black"]

HEADER_END = "END COMBINATION HEADER DATUM"
MESSAGE_SIZE_DATA_END = "END MESSAGE SIZE DATUM"
CRYPTO_COMBO_END = "END COMBINATION DATUM"

class MessageDatum:

    def __init__(self, message_size, avg_time, secret_overhead, mac_overhead, total_message_size):
        self.message_size = message_size
        self.avg_time = avg_time
        self.secret_overhead = secret_overhead
        self.mac_overhead = mac_overhead
        self.total_message_size = total_message_size

    def get_total_memory_overhead(self):
        return self.secret_overhead + self.mac_overhead

    def time_to_send_mac(self, baud_rate):
        return round((float(self.mac_overhead * 8) / float(baud_rate)), 4)

    def time_to_send_secret(self, baud_rate):
        return round((float(self.secret_overhead * 8) / float(baud_rate)), 4)

    def time_to_send_overhead(self, baud_rate):
        return round(self.time_to_send_mac(baud_rate)\
                + self.time_to_send_secret(baud_rate), 4)

    def time_to_send_original_message(self, baud_rate):
        return round((float(self.message_size * 8 / float(baud_rate))), 4)

    def time_to_send_total_message(self, baud_rate):
        return round((float(self.total_message_size * 8 / float(baud_rate))), 4)

    def time_to_send_total_message_plus_secret(self, baud_rate):
        return round( 
                        (float(self.total_message_size * 8 / float(baud_rate)))
                        + self.time_to_send_secret(baud_rate)
                    , 4)

    def total_overhead_time(self, baud_rate):
        return round(self.time_to_send_secret(baud_rate)\
                + self.time_to_send_total_message(baud_rate)\
                + self.avg_time, 4);

    def to_string(self):
        return "" + str(self.message_size) + "\n"\
                    + str(self.avg_time) + "\n"\
                    + str(self.secret_overhead) + "\n"\
                    + str(self.mac_overhead) + "\n"\
                    + str(self.total_message_size) + "\n"

    def __str__(self):
        return str(self.get_total_memory_overhead())

    def __repr__(self):
        return str(self.get_total_memory_overhead())

def parse_crypto_combo_header(crypto_combo_header_lines):
    
    SECRET_GEN_STRING = "Secret Generator:"
    SYMMETRIC_STRING = "Symmetric Cipher:"
    MAC_STRING = "MAC:"

    output_str = ""

    for line in crypto_combo_header_lines:

        if line.find(SECRET_GEN_STRING) != -1:
            secret_index = line.find(SECRET_GEN_STRING)
            output_str += line[secret_index + len(SECRET_GEN_STRING):].strip()

        elif line.find(SYMMETRIC_STRING) != -1:
            symmetric_index = line.find(SYMMETRIC_STRING)
            output_str += ", "
            output_str += line[symmetric_index + len(SYMMETRIC_STRING):].strip()

        elif line.find(MAC_STRING) != -1:
            mac_index = line.find(MAC_STRING)
            output_str += ", "
            output_str += line[mac_index + len(MAC_STRING):].strip()

    return output_str

def parse_message_size_data(message_size_data_lines):
    
    MESSAGE_SIZE_STRING = "Message size of "
    BYTES_STRING = " bytes"

    AVG_TIME_STRING = "Average Time: "
    NANOSECONDS_STRING = " nanoseconds"

    SECRET_OVERHEAD_STRING = "Secret Overhead: "

    MAC_OVERHEAD_STRING = "MAC Overhead: "

    TOTAL_MESSAGE_SIZE_STRING = "Total Message Size: "

    message_size = 0
    avg_time = 0
    secret_overhead = 0
    mac_overhead = 0
    total_message_size = 0

    for line in message_size_data_lines:

        if line.find(MESSAGE_SIZE_STRING) != -1:
            message_size_index = line.find(MESSAGE_SIZE_STRING)
            bytes_index = line.find(BYTES_STRING)
            message_size = int(line[message_size_index + len(MESSAGE_SIZE_STRING):bytes_index])

        elif line.find(AVG_TIME_STRING) != -1:
            avg_time_index = line.find(AVG_TIME_STRING)
            nanoseconds_index = line.find(NANOSECONDS_STRING)
            avg_time = int(line[avg_time_index + len(AVG_TIME_STRING):nanoseconds_index])

        elif line.find(SECRET_OVERHEAD_STRING) != -1:
            secret_overhead_index = line.find(SECRET_OVERHEAD_STRING)
            bytes_index = line.find(BYTES_STRING)
            secret_overhead = int(line[secret_overhead_index + len(SECRET_OVERHEAD_STRING):bytes_index])

        elif line.find(MAC_OVERHEAD_STRING) != -1:
            mac_overhead_index = line.find(MAC_OVERHEAD_STRING)
            bytes_index = line.find(BYTES_STRING)
            mac_overhead = int(line[mac_overhead_index + len(MAC_OVERHEAD_STRING):bytes_index].strip())

        elif line.find(TOTAL_MESSAGE_SIZE_STRING) != -1:
            total_message_size_index = line.find(TOTAL_MESSAGE_SIZE_STRING)
            bytes_index = line.find(BYTES_STRING)
            end_index = total_message_size_index + len(TOTAL_MESSAGE_SIZE_STRING)
            total_message_size = int(line[end_index:bytes_index])

    return MessageDatum(message_size, (float(avg_time) / float(10**9)), secret_overhead, mac_overhead, total_message_size)

def parse_output(file_name):

    with open(file_name, 'r') as output_file:
        all_lines = [line.rstrip() for line in output_file]

    crypto_combo_data = {}

    temp_lines = []
    crypto_combo_key = ""
    message_data = []
    i = 0
    while i < len(all_lines):

        if all_lines[i] == HEADER_END:
            
            crypto_combo_key = parse_crypto_combo_header(temp_lines)
            temp_lines = []

        elif all_lines[i] == MESSAGE_SIZE_DATA_END:
            
            message_data.append(parse_message_size_data(temp_lines))
            temp_lines = []

        elif all_lines[i] == CRYPTO_COMBO_END:
            
            #Save off all message size data to a map
            crypto_combo_data[crypto_combo_key] = message_data
            message_data = []
            crypto_combo_key = ""

        else:

            temp_lines.append(all_lines[i])

        i += 1

    ##Verify
    """
    for key in crypto_combo_data.keys():
        
        print(key)

        for message_datum in crypto_combo_data[key]:
            print(message_datum.to_string())
    """

    return crypto_combo_data.keys(), crypto_combo_data

############################################################################################
##########----------------PRINT OUT DATA FOR SPECIFIC TABLES------------------##############
############################################################################################

def orig_message_size_vs_mem_overhead(combo, message_datum_list, baud_rates=None):

    datum = message_datum_list[0]
    sys.stdout.write(combo + " & " + str(datum.get_total_memory_overhead()) + "\\\\\n\hline\n")

def orig_message_size_vs_sending_overhead_with_baud_rates(combo, message_datum_list, baud_rates):

    #print("Baud Rate: " + str(baud_rate))
    datum = message_datum_list[0]
    sys.stdout.write(combo)
    for baud_rate in baud_rates:
        sys.stdout.write(" & " + str(datum.time_to_send_secret(baud_rate)) + " s")
    sys.stdout.write(" & " + str(float(sum([datum.time_to_send_secret(b) for b in baud_rates])) / float(len(baud_rates))) + " s")
    sys.stdout.write("\\\\\n\hline\n")

############################################################################################
##########----------------PRINT OUT DATA FOR SPECIFIC GRAPHS------------------##############
############################################################################################

def orig_message_size_vs_comp_overhead(message_datum_list, baud_rates=None):
    
    for datum in message_datum_list:
        sys.stdout.write("(" + str(datum.message_size) + ", " + str(datum.avg_time) + ")")

def orig_message_size_vs_comp_time_per_byte(message_datum_list, baud_rates=None):
    
    for datum in message_datum_list:
        sys.stdout.write("(" + str(datum.message_size) + ", "
            + str(float(datum.avg_time) / float(datum.message_size)) + ")")

def orig_message_size_vs_total_overhead_time(message_datum_list, baud_rates):

    for baud_rate in baud_rates:
        #print("Baud Rate: " + str(baud_rate))
        for datum in message_datum_list:
            sys.stdout.write("(" + str(datum.message_size) + ", " + str(datum.total_overhead_time(baud_rate)) + ")")

def format_table_data(keys, crypto_combo_data, baud_rates, data_format_function):
    
    keys.sort()

    CRYPTO_COMBO_TABLE_HEADER = "Crypto-Primitive Combinations"
    BYTES_OF_OVERHEAD_HEADER = "Bytes of Overhead"

    if data_format_function == orig_message_size_vs_sending_overhead_with_baud_rates:
        
        sys.stdout.write("\\begin{longtable} {| l ||")
        for i in range(0, len(baud_rates)):
            sys.stdout.write(" l |")
        sys.stdout.write(" l |")
        sys.stdout.write("}\n\hline\n")        

        sys.stdout.write(CRYPTO_COMBO_TABLE_HEADER)
        for baud_rate in baud_rates:
            sys.stdout.write(" & " + str(baud_rate) + " bps")
        sys.stdout.write(" & Average")
        sys.stdout.write("\\\\\n\hline\n")

        #Print out every row of the table
        temp_tuple_list = []
        for key in keys:
            message_datum_list = crypto_combo_data[key]
            temp_tuple_list.append((key, message_datum_list[0]))

        #Sort by the average message overhead across all baud rates
        temp_tuple_list.sort(key=lambda x: float(sum([x[1].time_to_send_secret(b) for b in baud_rates])) / float(len(baud_rates)),
                                reverse=True)

        for tup in temp_tuple_list:
            data_format_function(tup[0], [tup[1]], baud_rates)    

    elif data_format_function == orig_message_size_vs_mem_overhead:

        sys.stdout.write("\\begin{longtable} {| l ||")
        sys.stdout.write(" c |")
        sys.stdout.write("}\n\hline\n")

        sys.stdout.write(CRYPTO_COMBO_TABLE_HEADER)
        sys.stdout.write(" & " + BYTES_OF_OVERHEAD_HEADER)
        sys.stdout.write("\\\\\n\hline\n")
    
        temp_tuple_list = []
        for key in keys:
            message_datum_list = crypto_combo_data[key]
            temp_tuple_list.append((key, message_datum_list[0]))

        temp_tuple_list.sort(key=lambda x: x[1].get_total_memory_overhead(), reverse=True)

        for tup in temp_tuple_list:
            data_format_function(tup[0], [tup[1]], baud_rates)

    sys.stdout.write("\\caption{%s}\n" % get_graph_header_string(data_format_function))
    sys.stdout.write("\\end{longtable}\n")

    
def format_graph_data_key_agree(keys, 
                                crypto_combo_data, 
                                baud_rates, 
                                data_format_function, 
                                graph_title,
                                x_axis_label, 
                                y_axis_label):

    global PLOT_MARKS

    #Figure latex code
    #sys.stdout.write("\\begin{figure}[f]")

    #plot latex code
    sys.stdout.write("\\begin{tikzpicture}\n")
    sys.stdout.write("\\begin{axis}[\n")
    sys.stdout.write("\t/pgf/number format/.cd,fixed,precision=4,\n")
    sys.stdout.write("\ttitle={%s},\n" % graph_title)
    sys.stdout.write("\txlabel={%s},\n" % x_axis_label)
    sys.stdout.write("\tylabel={%s},\n" % y_axis_label)
    sys.stdout.write("\txmin=, xmax=,\n")
    sys.stdout.write("\tymin=, ymax=,\n")
    sys.stdout.write("\txtick={},\n")
    sys.stdout.write("\tytick={},\n")
    #sys.stdout.write("\tlegend pos=outer north west,\n")
    sys.stdout.write("\tlegend style={\
at={(%s, %s)},\
anchor=north east},\n" % (x_leg_pos, y_leg_pos))
    sys.stdout.write("\tymajorgrids=true,\n")
    sys.stdout.write("\tgrid style=dashed,\n")
    sys.stdout.write("]\n")

    prev_key = None
    for key in keys:
        
        #Differentiation by KeyAgreement (COLORS)
        if key.find(ECDH) != -1:
            color = "red"
        elif key.find(ESDH) != -1:
            color = "blue"
        elif key.find(ECMQV) != -1:
            color = "green"
        elif key.find(STATIC_KEY) != -1:
            color = "pink"

        #Differentiation by Symmetric Crypto (MARKS)
        if key.find(AES) != -1:
            mark = "+"
        elif key.find(BLOWFISH) != -1:
            mark = "x"
        elif key.find(SALSA) != -1:
            mark = "triangle"
        elif key.find(SOSE) != -1:
            mark = "square"

        #Differentiation by MAC (LINE STYLE)
        if key.find(HMAC) != -1:
            pass
        elif key.find(CMAC) != -1:
            linestyle = "dashed, "
        elif key.find(VMAC) != -1:
            linestyle = "dotted, "

        key_key_agreement = ""
        key_key_agreement = key[:key.find(',')]
        prev_key_key_agreement = "not key key agreement"
        if prev_key is not None:            
            prev_key_key_agreement = prev_key[:prev_key.find(',')]

        sys.stdout.write("\\addplot[\n")
        sys.stdout.write("%s" % linestyle)
        sys.stdout.write("\tcolor=%s,\n" % color)
        sys.stdout.write("\tmark=%s,\n" % mark)
        if prev_key is not None and key_key_agreement == prev_key_key_agreement:
            sys.stdout.write("forget plot, \n")
        sys.stdout.write("\t]\n")
        sys.stdout.write("coordinates {")

        message_datum_list = crypto_combo_data[key]
        data_format_function(message_datum_list, baud_rates)

        sys.stdout.write("};\n")

        if prev_key is None or key_key_agreement != prev_key_key_agreement:
            sys.stdout.write("\\addlegendentry{%s}\n" % key_key_agreement)

        prev_key = key

    sys.stdout.write("\\end{axis}\n")
    sys.stdout.write("\\end{tikzpicture}\n")
    #End plot

    #sys.stdout.write("\\caption{%s}\n" % get_graph_header_string(data_format_function))
    #sys.stdout.write("\\end{figure}")
    #End Figure

def format_graph_data_symmetric(keys, 
                                crypto_combo_data, 
                                baud_rates, 
                                data_format_function, 
                                graph_title,
                                x_axis_label, 
                                y_axis_label):

    global PLOT_MARKS

    #Figure latex code
    #sys.stdout.write("\\begin{figure}[f]")

    #plot latex code
    sys.stdout.write("\\begin{tikzpicture}\n")
    sys.stdout.write("\\begin{axis}[\n")
    sys.stdout.write("\t/pgf/number format/.cd,fixed,precision=4,\n")
    sys.stdout.write("\ttitle={%s},\n" % graph_title)
    sys.stdout.write("\txlabel={%s},\n" % x_axis_label)
    sys.stdout.write("\tylabel={%s},\n" % y_axis_label)
    sys.stdout.write("\txmin=, xmax=,\n")
    sys.stdout.write("\tymin=, ymax=,\n")
    sys.stdout.write("\txtick={},\n")
    sys.stdout.write("\tytick={},\n")
    #sys.stdout.write("\tlegend pos=outer north west,\n")
    sys.stdout.write("\tlegend style={\
at={(%s,%s)},\
anchor=north east},\n" % (x_leg_pos, y_leg_pos))
    sys.stdout.write("\tymajorgrids=true,\n")
    sys.stdout.write("\tgrid style=dashed,\n")
    sys.stdout.write("]\n")

    prev_key = None
    for key in keys:

        #Differentiation by Symmetric Crypto (MARKS)
        if key.find(AES) != -1:
            color = "red"
        elif key.find(BLOWFISH) != -1:
            color = "blue"
        elif key.find(SALSA) != -1:
            color = "green"
        elif key.find(SOSE) != -1:
            color = "pink"


        #Differentiation by MAC (LINE STYLE)
        if key.find(HMAC) != -1:
            mark = "oplus"
        elif key.find(CMAC) != -1:
            mark = "x"
        elif key.find(VMAC) != -1:
            mark = "diamond"

        sys.stdout.write("\\addplot[\n")
        #sys.stdout.write("%s" % linestyle)
        sys.stdout.write("\tcolor=%s,\n" % color)
        sys.stdout.write("\tmark=%s,\n" % mark)
        sys.stdout.write("\t]\n")
        sys.stdout.write("coordinates {")

        message_datum_list = crypto_combo_data[key]
        data_format_function(message_datum_list, baud_rates)

        sys.stdout.write("};\n")

        sys.stdout.write("\\addlegendentry{%s}\n" % key)

        prev_key = key

    sys.stdout.write("\\end{axis}\n")
    sys.stdout.write("\\end{tikzpicture}\n")
    #End plot

    #sys.stdout.write("\\caption{%s}\n" % get_graph_header_string(data_format_function))
    #sys.stdout.write("\\end{figure}")
    #End Figure

def get_graph_header_string(data_format_function):
    if data_format_function == orig_message_size_vs_total_overhead_time:
        return "ORIGINAL MESSAGE SIZE VS TOTAL OVERHEAD TIME (COMMUNICATIONS AND COMPUTATIONAL)"
    elif data_format_function == orig_message_size_vs_comp_time_per_byte:
        return "ORIGINAL MESSAGE SIZE VS COMPUTATIONAL OVERHEAD TIME PER BYTE"
    elif data_format_function == orig_message_size_vs_comp_overhead:
        return "ORIGINAL MESSAGE SIZE VS COMPUTATIONAL OVERHEAD TIME"
    elif data_format_function == orig_message_size_vs_sending_overhead_with_baud_rates:
        return "ORIGINAL MESSAGE SIZE VS SEND OVERHEAD (using baud rate)"
    elif data_format_function == orig_message_size_vs_mem_overhead:
        return "ORIGINAL MESSAGE SIZE VS MEMORY OVERHEAD"

def print_all_graph_data(keys, crypto_combo_data, baud_rates):

        #Table values
        format_table_data(keys, 
                            crypto_combo_data, 
                            baud_rates, 
                            orig_message_size_vs_mem_overhead)
        print("\n\n")
        format_table_data(keys, 
                            crypto_combo_data, 
                            baud_rates, 
                            orig_message_size_vs_sending_overhead_with_baud_rates)
        print("\n\n")

        #Graph labels
        X_ORIG_MSG_SIZE = "Original Message Size (bytes)"
        Y_COMP_OVERHEAD = "Computational Overhead (seconds)"
        Y_COMP_PER_BYTE = "Computation Time per byte (seconds/byte)"
        Y_TOTAL_TIME = "Total Overhead Time (seconds)"

        #Graph Values
        format_graph_data_key_agree(keys, 
                            crypto_combo_data, 
                            baud_rates, 
                            orig_message_size_vs_comp_overhead,
                            "Message Size vs. Computational Overhead",
                            X_ORIG_MSG_SIZE,
                            Y_COMP_OVERHEAD)
        print("\n\n")
        format_graph_data_key_agree(keys, 
                            crypto_combo_data, 
                            baud_rates, 
                            orig_message_size_vs_comp_time_per_byte,
                            "Message Size vs. Computational Time per Byte",
                            X_ORIG_MSG_SIZE,
                            Y_COMP_PER_BYTE)
        print("\n\n")
        format_graph_data_key_agree(keys, 
                                    crypto_combo_data, 
                                    baud_rates, 
                                    orig_message_size_vs_total_overhead_time,
                                    "Message Size vs. Total Overhead Time (Computation and Communication)",
                                    X_ORIG_MSG_SIZE,
                                    Y_TOTAL_TIME)

        #KEY AGREEMENT SPECIFIC
        print("\n\n")
        edh_keys = []
        for key in keys:
            if key.find(ESDH) != -1:
                edh_keys.append(key)
        format_graph_data_symmetric(edh_keys,
                                    crypto_combo_data,
                                    baud_rates,
                                    orig_message_size_vs_comp_overhead,
                                    "Message Size vs. Computational Overhead (EDH)",
                                    X_ORIG_MSG_SIZE,
                                    Y_COMP_OVERHEAD)
        print("\n\n")
        ecmqv_keys = []
        for key in keys:
            if key.find(ECMQV) != -1:
                ecmqv_keys.append(key)
        format_graph_data_symmetric(ecmqv_keys,
                                    crypto_combo_data,
                                    baud_rates,
                                    orig_message_size_vs_comp_overhead,
                                    "Message Size vs. Computational Overhead (ECMQV)",
                                    X_ORIG_MSG_SIZE,
                                    Y_COMP_OVERHEAD)

        print("\n\n")
        static_keys = []
        for key in keys:
            if key.find(STATIC_KEY) != -1:
                static_keys.append(key)
        format_graph_data_symmetric(static_keys,
                                    crypto_combo_data,
                                    baud_rates,
                                    orig_message_size_vs_comp_overhead,
                                    "Message Size vs. Computational Overhead (STATIC KEYS)",
                                    X_ORIG_MSG_SIZE,
                                    Y_COMP_OVERHEAD)

        #KEY AGREEMENT SPECIFIC (MINUS SOSEMANUK)
        print("\n\n")
        ecmqv_keys_sos = []
        for key in ecmqv_keys:
            if key.find("Sosemanuk, VMAC") == -1:
                ecmqv_keys_sos.append(key)
        format_graph_data_symmetric(ecmqv_keys_sos,
                                    crypto_combo_data,
                                    baud_rates,
                                    orig_message_size_vs_comp_overhead,
                                    "Message Size vs. Computational Overhead (ECMQV) (SOSEMANUK, VMAC REMOVED)",
                                    X_ORIG_MSG_SIZE,
                                    Y_COMP_OVERHEAD)

        #MAC Specific
        print("\n\n")
        ecmqv_salsa_keys = []
        for key in ecmqv_keys:
            if key.find("Salsa20") != -1:
                ecmqv_salsa_keys.append(key)
        format_graph_data_symmetric(ecmqv_salsa_keys,
                                    crypto_combo_data,
                                    baud_rates,
                                    orig_message_size_vs_comp_overhead,
                                    "Message Size vs. Computational Overhead (ECMQV, Salsa)",
                                    X_ORIG_MSG_SIZE,
                                    Y_COMP_OVERHEAD)

        print("\n\n")
        ecmqv_AES_keys = []
        for key in ecmqv_keys:
            if key.find("AES") != -1:
                ecmqv_AES_keys.append(key)
        format_graph_data_symmetric(ecmqv_AES_keys,
                                    crypto_combo_data,
                                    baud_rates,
                                    orig_message_size_vs_comp_overhead,
                                    "Message Size vs. Computational Overhead (ECMQV, AES)",
                                    X_ORIG_MSG_SIZE,
                                    Y_COMP_OVERHEAD)

        print("\n\n")
        edh_salsa_keys = []
        for key in edh_keys:
            if key.find("Salsa20") != -1:
                edh_salsa_keys.append(key)
        format_graph_data_symmetric(edh_salsa_keys,
                                    crypto_combo_data,
                                    baud_rates,
                                    orig_message_size_vs_comp_overhead,
                                    "Message Size vs. Computational Overhead (EDH, Salsa)",
                                    X_ORIG_MSG_SIZE,
                                    Y_COMP_OVERHEAD)

        print("\n\n")
        edh_AES_keys = []
        for key in edh_keys:
            if key.find("AES") != -1:
                edh_AES_keys.append(key)
        format_graph_data_symmetric(edh_AES_keys,
                                    crypto_combo_data,
                                    baud_rates,
                                    orig_message_size_vs_comp_overhead,
                                    "Message Size vs. Computational Overhead (EDH, AES)",
                                    X_ORIG_MSG_SIZE,
                                    Y_COMP_OVERHEAD)

if __name__ == '__main__':
    
    keys, crypto_combo_data = parse_output("sim-test.output--old")
    baud_rates = [1200, 2400, 4800, 9600, 19200]

    print_all_graph_data(keys, crypto_combo_data, baud_rates)
