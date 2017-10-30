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
 * @author Ovidiu Feodorov <ovidiu@novaordis.com>
 * @since 10/30/17
 */
public enum ConnectionState {

    // Constants -------------------------------------------------------------------------------------------------------

    CLOSED,
    CLOSE_WAIT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    LAST_ACK,
    LISTENING,
    SYN_RECEIVED,
    SYN_SENT,
    TIME_WAIT

    // Static ----------------------------------------------------------------------------------------------------------

    // Public ----------------------------------------------------------------------------------------------------------

}
