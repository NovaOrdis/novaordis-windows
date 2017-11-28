/*
 * Copyright (c) 2017 Nova Ordis LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.novaordis.windows.netstat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Windows netstat output parsing logic.
 *
 * @author Ovidiu Feodorov <ovidiu@novaordis.com>
 * @since 9/9/17
 */
public class Netstat {

    // Constants -------------------------------------------------------------------------------------------------------

    public static final Map<String, Integer> STANDARD_PORTS = new HashMap<>();
    public static final Set<String> LOCAL_HOST_ADDRESSES = new HashSet<>();

    static {

        STANDARD_PORTS.put("ingreslock", 1524);
        STANDARD_PORTS.put("ms-sql-s", 1433);
        STANDARD_PORTS.put("nfsd-status", 1110);
        STANDARD_PORTS.put("ms-sna-base", 1478);
        STANDARD_PORTS.put("ms-sna-server", 1477);
        STANDARD_PORTS.put("wins", 1512);
        STANDARD_PORTS.put("pptconference", 1711);
        STANDARD_PORTS.put("pptp", 1723);
        STANDARD_PORTS.put("msiccp", 1731);
        STANDARD_PORTS.put("remote-winsock", 1745);
        STANDARD_PORTS.put("ms-streaming", 1755);
        STANDARD_PORTS.put("msmq", 1801);
        STANDARD_PORTS.put("msnp", 1863);
        STANDARD_PORTS.put("ssdp", 1900);
        STANDARD_PORTS.put("knetd", 2053);
        STANDARD_PORTS.put("man", 9535);

//        LOCAL_HOST_ADDRESSES.add("GBDC1-PLMPRD-1");
//        LOCAL_HOST_ADDRESSES.add("10.103.0.130");
//        LOCAL_HOST_ADDRESSES.add("127.0.0.1");
    }

    // Static ----------------------------------------------------------------------------------------------------------

    private static boolean headerDisplayed = false;


    public static void parse(String[] args) throws Exception {

        String filename = args[0];

        File f = new File(filename);

        BufferedReader br = new BufferedReader(new FileReader(f));

        String line;

        int lineNumber = 0;

        TimestampInfo currentTimestampInfo = null;

        Connection current = null;

        List<Connection> connections = new ArrayList<>();

        while((line = br.readLine()) != null) {

            lineNumber ++;

            line = line.trim();

            if (line.isEmpty()) {

                continue;
            }

            if (TimestampInfo.isDateLine(line)) {

                //
                // display the statistics for the previous reading
                //

                if (currentTimestampInfo != null) {

                    displayStatistics(currentTimestampInfo, connections);

                    //
                    // reset data and prepare it for the next reading
                    //

                    connections.clear();
                }

                currentTimestampInfo = new TimestampInfo(line);
            }
            else if (TimestampInfo.isTimeLine(line)) {

                //noinspection ConstantConditions
                currentTimestampInfo.setTime(line);
            }
            else if (line.startsWith(ConnectionType.TCP.name())) {

                if (current != null) {

                    //
                    // new connection report starts, save the current one
                    //

                    connections.add(current);
                }

                current = new Connection(lineNumber, line);
            }
            else if (current != null) {

                current.add(lineNumber, line);
            }
        }

        br.close();

        if (currentTimestampInfo != null) {

            //
            // display statistics for the last reading
            //
            displayStatistics(currentTimestampInfo, connections);
        }
    }

    private static void displayStatistics(TimestampInfo ti, List<Connection> connections) {

        ConnectionState[] states = {

                ConnectionState.ESTABLISHED,
                ConnectionState.LISTENING,
                ConnectionState.TIME_WAIT,
                ConnectionState.CLOSED,
                ConnectionState.CLOSE_WAIT,
                ConnectionState.CLOSING,
                ConnectionState.FIN_WAIT_1,
                ConnectionState.FIN_WAIT_2,
                ConnectionState.LAST_ACK,
                ConnectionState.SYN_RECEIVED,
                ConnectionState.SYN_SENT,
        };

        if (!headerDisplayed) {

            headerDisplayed = true;

            System.out.print("# time, ");

            for(ConnectionState s: states) {

                System.out.print(s.name() + " (total), ");
            }

            for(ConnectionState s: states) {

                System.out.print(s.name() + " (java), ");
            }

            System.out.println();
        }

        System.out.print(TimestampInfo.TIMESTAMP_OUTPUT_FORMAT.format(ti.getTimestamp()) + ", ");

        for(ConnectionState s: states) {

            int c = getCount(connections, s, null);

            System.out.print(c + ", ");
        }

        for(ConnectionState s: states) {

            int c = getCount(connections, s, "java.exe");

            System.out.print(c + ", ");
        }

        System.out.println();
    }

    /**
     * @param process may be null, and in this case all connections in the given state are counted.
     */
    private static int getCount(List<Connection> connections, ConnectionState state, String process) {

        int count = 0;

        for(Connection c: connections) {

            ConnectionState s = c.getState();

            if (!s.equals(state)) {

                continue;
            }

            if (process == null) {

                count++;
            }
            else {

                String cp = c.getProcess();

                if (process.equals(cp)) {

                    count ++;
                }
            }
        }

        return count;
    }

    // Attributes ------------------------------------------------------------------------------------------------------

    // Constructors ----------------------------------------------------------------------------------------------------

    // Public ----------------------------------------------------------------------------------------------------------

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------

    private static class TimestampInfo {

        public static final Pattern DATE_PATTERN = Pattern.compile("^[0-3][0-9]/[0-1][0-9]/\\d\\d\\d\\d.*");
        public static final Pattern TIME_PATTERN = Pattern.compile("^[0-2]\\d:\\d\\d.*");

        public static final SimpleDateFormat TIMESTAMP_INPUT_FORMAT = new SimpleDateFormat("dd/MM/yyyy HH:mm");
        public static final SimpleDateFormat TIMESTAMP_OUTPUT_FORMAT = new SimpleDateFormat("MM/dd/YY HH:mm");

        /**
         * Return true if the line starts with date info.
         */
        public static boolean isDateLine(String line) {

            Matcher m = DATE_PATTERN.matcher(line);
            return m.matches();
        }

        /**
         * Return true if the line starts with date info.
         */
        public static boolean isTimeLine(String line) {

            Matcher m = TIME_PATTERN.matcher(line);
            return m.matches();
        }

        private String dateString;
        private String timeString;
        private long timestamp;

        public TimestampInfo(String line) {

            this.dateString = line.trim();
        }

        public void setTime(String line) throws ParseException {

            this.timeString = line.trim();

            String s = dateString + " " + timeString;

            this.timestamp = TIMESTAMP_INPUT_FORMAT.parse(s).getTime();
        }

        public long getTimestamp() {

            return timestamp;
        }

    }

}
