@load remote_logging/remote_logger

const broker_port: port = 9998/tcp &redef;
redef BrokerComm::endpoint_name = "connector";
redef Log::enable_local_logging = F;
redef Log::enable_remote_logging = F;

event bro_init() &priority=5
	{
	BrokerComm::enable();
	BrokerComm::enable_remote_logs(BrokLog::LOG);
	BrokerComm::connect("127.0.0.1", broker_port, 1sec);
	}

event do_write(L: BrokLog::Info)
	{
	Log::write(BrokLog::LOG, L);
	print fmt("LOGGING: %s", L);
	}
