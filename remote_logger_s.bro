@load remote_logging/remote_logger

const broker_port: port = 9998/tcp &redef;
redef BrokerComm::endpoint_name = "listener";

event BrokLog::log_test(rec: BrokLog::Info)
	{
	print "wrote log", rec;
	}

event bro_init() &priority=5
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_logs("bro/log/BrokLog::LOG");
	BrokerComm::listen(broker_port, "127.0.0.1");
	}
