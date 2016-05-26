module BrokLog;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		note: string &log &default="NULL";
		user: string &log &default="NULL";
		AS: string &log &default="NULL";
		CC: string &log &default="NULL";
		City: string &log &default="NULL";
		Region: string &log &default="NULL";
		PrevCC: string &log &default="NULL";
		auth: string &log &default="NULL";
		misc: string &log &default="NULL";
		};

	global log_test: event(rec: BrokLog::Info);
}

event bro_init() &priority=5
	{
	BrokerComm::enable();
	Log::create_stream(BrokLog::LOG, [$columns=BrokLog::Info, $ev=log_test, $path="broker_log"]);
	}
