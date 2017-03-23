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
import java.util.ArrayList;
import java.util.List;

import com.splunk.Args;
import com.splunk.ReceiverBehavior;
import com.splunk.Service;

public class JSONEvents implements EventProcessor {
	XIndex index;
	Service service;
	Args args = new Args();
	List<String> events = new ArrayList<>();
	
	public JSONEvents(Service service, String index, String source) {
		this.service = service;
		this.index = new XIndex(service.getIndexes().get(index));
		this.args.add("host", "atomikron");
		this.args.add("sourcetype", "json");
		this.args.add("source", source);
	}

	@Override
	public boolean addline(String line) throws Exception {
		try {
			events.add(line);
		} catch (Exception e) { return false; }
		return false;
	}
	
	public boolean addline(List<String> merge) {
		try {
			events.addAll(merge);
		} catch(Exception e) { return false; }
		return true;
	}

	@Override
	public void submit() throws Exception {
		index.attachWith(args, new ReceiverBehavior() {
			@Override public void run(OutputStream stream) throws IOException {
				for(String event: events) {
					event += "\n";
					stream.write(event.getBytes("UTF8"));
				}
				events.clear();
			}
		});
	}

}
