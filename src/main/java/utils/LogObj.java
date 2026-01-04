package utils;

import java.text.SimpleDateFormat;
import java.util.Date;

public class LogObj {

    public static final LogObj defaultLog = new LogObj();

    private String _name;

    public LogObj(){
        this._name = null;
    }

    public LogObj(String name){
        this._name = name;
    }

    public void setName(String name) {
        this._name = name;
    }

    public void info(Object msg){
        Logging.log(getLog("INFO", "", msg));
    }

    public void info(String extraName, Object msg){
        Logging.log(getLog("INFO", extraName, msg));
    }

    public void warn(Object msg){
        Logging.warn(getLog("WARN", "", msg));
    }

    public void warn(String extraName, Object msg){
        Logging.warn(getLog("WARN", extraName, msg));
    }

    public void error(Object msg){
        Logging.error(getLog("ERROR", "", msg));
    }

    public void error(String extraName, Object msg){
        Logging.error(getLog("ERROR", extraName, msg));
    }

    private String getLog(String pad, String extraName, Object msg){
        var l = String.format("[%s] %s", pad, extraName);
        return String.format(
                "(GL)[%s]%s " + "%s" + "%s" + "%s"
                , pad
                , FormatDate(new Date())
                , (_name != null ? "[" + _name + "]" : "")
                , (!extraName.isEmpty() ? "[" + extraName + "]" : "")
                , msg);
    }

    private String FormatDate(Date date){
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        return formatter.format(date);
    }
}
