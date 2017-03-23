/*  
  Copyright (C) 2017 William Welna (wwelna@occultusterra.com)
  
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

  https://github.com/Sanguinarious/atomikron
*/

package com.occultusterra.watchdog.atomikron;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

import com.splunk.Args;
import com.splunk.Index;
import com.splunk.ReceiverBehavior;

public class XIndex {
	Index index;

	XIndex(Index index) {
		this.index = index;
	}
	
   public void attachWith(Args args, ReceiverBehavior behavior) throws IOException {
        Socket socket = null;
        OutputStream output = null;
        try {
            socket = index.attach(args);
            output = socket.getOutputStream();
            behavior.run(output);
            output.flush();
        } finally {
            if (output != null) { output.close(); }
            if (socket != null) { socket.close(); }
        }
    }

}
