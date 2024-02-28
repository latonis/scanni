use windows::Win32::System::Antimalware;
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Etw;

fn main() {
    unsafe {

        // TODO: Trace ETW and grokk ouputs
        // Etw::StartTraceA(0, "scanni", properties);
        let appname_raw: Vec<u16>  = "scanni".encode_utf16().collect();
        let appname = PCWSTR(appname_raw.as_ptr());
        let eicar: Vec<u16> = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode_utf16().chain(std::iter::once(0)).collect();
        
        let context = Antimalware::AmsiInitialize(appname).unwrap();

        let session = Antimalware::AmsiOpenSession(context).unwrap();

        let result = Antimalware::AmsiScanString(context, PCWSTR(eicar.as_ptr()), appname, session).unwrap();
        
        let is_malware = result.0 >= 32768;

        println!("Is Malware? {}", is_malware);

        // TODO: End ETW trace
    };
    
    println!("Hello, AMSI Scanning!");
}
