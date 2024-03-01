use windows::core::PCWSTR;
use windows::Win32::Foundation;
use windows::Win32::System::Antimalware;
use windows::Win32::System::Diagnostics::Etw::{self, EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING};

fn main() {
    unsafe {
        let appname_raw: Vec<u16> = "scanni".encode_utf16().chain(std::iter::once(0)).collect();
        let appname = PCWSTR(appname_raw.as_ptr());
        let eicar: Vec<u16> =
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
        let mut tracehandle = Etw::CONTROLTRACE_HANDLE { Value: 0 };
        let mut properties: Etw::EVENT_TRACE_PROPERTIES = TraceProps::default().into();

        let err = Etw::StartTraceW(&mut tracehandle, appname, &mut properties);

        match err {
            Foundation::ERROR_SUCCESS => {
                dbg!("StartTraceA initialized successfully!", tracehandle);
            }
            Foundation::ERROR_ALREADY_EXISTS => {
                dbg!("Trace already exists!");
            }
            _ => {
                dbg!("AHHH unexpected error in ETW", err);
            }
        }

        // Microsoft-Antimalware-Scan-Interface - {2A576B87-09A7-520E-C21A-4942F0271D67}
        // (https://docs.velociraptor.app/exchange/artifacts/pages/amsi/)
        
        let context = Antimalware::AmsiInitialize(appname).unwrap();

        let session = Antimalware::AmsiOpenSession(context).unwrap();

        let result =
            Antimalware::AmsiScanString(context, PCWSTR(eicar.as_ptr()), appname, session).unwrap();
        // TODO Read from ETW

        let is_malware = result.0 >= 32768;
        println!("Is Malware? {}", is_malware);

        Etw::StopTraceW(tracehandle, appname, &mut properties);
        Etw::CloseTrace(Etw::PROCESSTRACE_HANDLE {
            Value: tracehandle.Value,
        });
    };

    println!("Hello, AMSI Scanning!");
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
#[derive(Debug)]
struct TraceProps {
    buffer_size: u32,
    minimum_buffers: u32,
    maximum_buffers: u32,
    flush_timer: u32,
}

impl Default for TraceProps {
    fn default() -> Self {
        TraceProps {
            buffer_size: 32,
            minimum_buffers: 0,
            maximum_buffers: 0,
            flush_timer: 1,
        }
    }
}

impl From<TraceProps> for Etw::EVENT_TRACE_PROPERTIES {
    fn from(trace_props: TraceProps) -> Self {
        let wnode = Etw::WNODE_HEADER {
            BufferSize: 1024 as u32,
            ..Default::default()
        };

        Etw::EVENT_TRACE_PROPERTIES {
            Wnode: wnode,
            BufferSize: trace_props.buffer_size,
            MinimumBuffers: trace_props.minimum_buffers,
            MaximumBuffers: trace_props.maximum_buffers,
            FlushTimer: trace_props.flush_timer,
            LogFileMode: (Etw::EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING),
            ..Default::default()
        }
    }
}
