import logging

class HostCounterCheck:
    """ Class to check if the host suffers packet losses """
    def __init__(self):
        return

    def check_no_packet_loss_tx(self, requester_counter, responder_counter):
        """ Check if there is any packet loss at the host TX

        Args:
            requester_counter (HostCounter): Counters retrieved from RDMA requester
            responder_counter (HostCounter): Counters retrieved from RDMA responder

        Returns:
            bool: True if there is no packet loss
        """
        result = True
        logging.info("Checking host TX packet loss")

        requester_counter_discards_dict = requester_counter.get_num_discards_dict_tx()
        responder_counter_discards_dict = responder_counter.get_num_discards_dict_tx()

        for counter in requester_counter_discards_dict.keys():
            if requester_counter_discards_dict[counter] != 0:
                logging.error("There are packets discarded by the requester TX (%s:%d)"\
                              % (counter, requester_counter_discards_dict[counter]))
                result = False

        for counter in responder_counter_discards_dict.keys():
            if responder_counter_discards_dict[counter] != 0:
                logging.error("There are packets discarded by the responder TX (%s:%d)"\
                              % (counter, responder_counter_discards_dict[counter]))
                result = False

        return result

    def check_no_packet_loss_rx(self, requester_counter, responder_counter):
        """ Check if there is any packet loss at the host RX

        Args:
            requester_counter (HostCounter): Counters retrieved from RDMA requester
            responder_counter (HostCounter): Counters retrieved from RDMA responder

        Returns:
            bool: True if there is no packet loss
        """
        result = True
        logging.info("Checking host RX packet loss")

        requester_counter_discards_dict = requester_counter.get_num_discards_dict_rx()
        responder_counter_discards_dict = responder_counter.get_num_discards_dict_rx()

        for counter in requester_counter_discards_dict.keys():
            if requester_counter_discards_dict[counter] != 0:
                logging.error("There are packets discarded by the requester RX (%s:%d)"\
                              % (counter, requester_counter_discards_dict[counter]))
                result = False
        for counter in responder_counter_discards_dict.keys():
            if responder_counter_discards_dict[counter] != 0:
                logging.error("There are packets discarded by the responder RX (%s:%d)"\
                              % (counter, responder_counter_discards_dict[counter]))
                result = False

        return result

    def check_no_packet_loss(self, requester_counter, responder_counter):
        """ Check if there is any packet loss at the host

        Args:
            requester_counter (HostCounter): Counters retrieved from RDMA requester
            responder_counter (HostCounter): Counters retrieved from RDMA responder

        Returns:
            bool: True if there is no packet loss
        """
        logging.info("Checking host packet loss")
        tx_no_packet_loss = self.check_no_packet_loss_tx(requester_counter, responder_counter)
        rx_no_packet_loss = self.check_no_packet_loss_rx(requester_counter, responder_counter)
        return tx_no_packet_loss and rx_no_packet_loss
