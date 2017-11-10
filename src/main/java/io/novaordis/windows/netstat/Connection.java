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

/**
 * Represents an immutable /proc/stat "reading" - the state of the file at a certain moment in time.
 *
 * https://kb.novaordis.com/index.php//proc/stat#Contents
 *
 * TODO: support for "page", "swap", "intr", "ctxt", etc. not yet implemented.
 *
 * @author Ovidiu Feodorov <ovidiu@novaordis.com>
 * @since 9/9/17
 */
public class Connection {

    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // TCP, UDP
    private ConnectionType type;

    private ConnectionState state;

    private boolean listening;
    private boolean established;
    private String process;
    private String localHost;
    private int localPort;
    private String remoteHost;
    private int remotePort;

    // Constructors ----------------------------------------------------------------------------------------------------

    public Connection(long lineNumber, String line) throws Exception {

        if (line.startsWith(ConnectionType.TCP.name())) {

            type = ConnectionType.TCP;
        }
        else if (line.startsWith(ConnectionType.UDP.name())) {

            type = ConnectionType.UDP;
        }
        else {

            throw new Exception("line " + lineNumber + ": unknown connection type: " + line);
        }

        line = line.substring(type.name().length()).trim();

        //
        // state
        //

        int i = line.lastIndexOf(' ');

        if (i == -1) {

            throw new Exception("line " + lineNumber + ": no space separator identified");
        }

        String stateString = line.substring(i + 1);

        try {

            this.state = ConnectionState.valueOf(stateString);
        }
        catch(IllegalArgumentException e) {

            throw new Exception("line " + lineNumber + ": " + "invalid state: " + stateString);
        }

        line = line.substring(0, i);

        //
        // process the rest of the line
        //

        // 1.2.3.4:80        1.2.3.5:61122

        i = line.indexOf(' ');

        if (i == -1) {

            throw new Exception("line " + lineNumber + ": missing space separator between local address and remote address");
        }

        String local = line.substring(0, i).trim();
        String remote = line.substring(i).trim();

        i = local.lastIndexOf(':');

        if (i == -1) {

            throw new Exception("line " + lineNumber + ": missing ':' separator in the local address");
        }

        this.localHost = local.substring(0, i);

        String lp = local.substring(i + 1);

        try {

            this.localPort = Integer.parseInt(lp);
        }
        catch(Exception e) {

            //
            // attempt standard ports
            //

            Integer p = Netstat.STANDARD_PORTS.get(lp);

            if (p == null) {

                throw new Exception("line " + lineNumber + ": unknown standard local port " + lp);
            }

            this.localPort = p;
        }

        i = remote.lastIndexOf(':');

        if (i == -1) {

            throw new Exception("line " + lineNumber + ": missing ':' separator in the remote address");
        }

        this.remoteHost = remote.substring(0, i);
        String rp = remote.substring(i + 1);

        try {

            this.remotePort = Integer.parseInt(rp);
        }
        catch(Exception e) {

            //
            // attempt standard ports
            //

            Integer p = Netstat.STANDARD_PORTS.get(rp);

            if (p == null) {

                throw new Exception("line " + lineNumber + ": unknown standard remote port " + rp);
            }

            this.remotePort = p;
        }
    }

    // Public ----------------------------------------------------------------------------------------------------------

    public void add(long lineNumber, String line) throws Exception {

        line = line.trim();

        if (!line.startsWith("[")) {

            return;
        }

        line = line.substring(1);

        if (!line.endsWith("]")) {

            throw new Exception("line: " + lineNumber + ": invalid process");
        }

        process = line.substring(0, line.length() - 1);
    }

    public ConnectionState getState() {

        return state;
    }

    /**
     * May return null.
     */
    public String getProcess() {

        return process;
    }

    public String getLocalHost() {

        return localHost;
    }

    public int getLocalPort() {

        return localPort;
    }

    public String getRemoteHost() {

        return remoteHost;
    }

    public int getRemotePort() {

        return remotePort;
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------

}
