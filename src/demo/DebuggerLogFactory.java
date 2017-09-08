package demo;

import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogLevel;

import java.util.Iterator;

/**
 * enable the debug log level hope this will help you to get out what's happening
 * Created by edward.gao on 08/09/2017.
 */
public class DebuggerLogFactory extends ConsoleLogFactory {

    @Override
    public LogAdapter getRootLogger() {
        return _getDebugEnabledLogger();
    }


    private LogAdapter _getDebugEnabledLogger() {
        LogAdapter logAdapter =  super.getRootLogger();
        logAdapter.setLogLevel(LogLevel.ALL);
        return logAdapter;
    }

    @Override
    protected LogAdapter createLogger(Class c) {
        return _getDebugEnabledLogger();
    }

    @Override
    protected LogAdapter createLogger(String className) {
        return _getDebugEnabledLogger();
    }

    @Override
    public Iterator loggers() {
        return super.loggers();
    }
}
