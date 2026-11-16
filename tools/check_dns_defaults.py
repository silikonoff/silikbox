"""Check one-way DNS migration with the real JVM class, without Android data."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
java_home = Path(os.environ["JAVA_HOME"])
source = root / "app/src/main/java/moe/matsuri/nb4a/net/DnsDefaults.java"
with tempfile.TemporaryDirectory(prefix="silikbox-dns-") as folder:
    folder = Path(folder)
    test = folder / "DnsDefaultsTest.java"
    test.write_text('''import moe.matsuri.nb4a.net.DnsDefaults;
public class DnsDefaultsTest {
 public static void main(String[] args) {
  String google="https://dns.google/dns-query";
  for(String old: new String[]{"https://223.5.5.5/dns-query", "223.6.6.6", "https://dns.alidns.com/dns-query"}) {
   if(!DnsDefaults.migrate(old).equals(google)) throw new AssertionError("retired default remains");
   if(!DnsDefaults.migrate("# comment\\n"+old+"\\nlocal\\n").equals("# comment\\n"+google+"\\nlocal\\n")) throw new AssertionError("multiline migration");
  }
  for(String custom: new String[]{"local", google, "https://resolver.example/custom", "# custom\\n9.9.9.9\\n", ""}) {
   if(!DnsDefaults.migrate(custom).equals(custom)) throw new AssertionError("custom setting changed");
  }
  System.out.println("DNS_DEFAULT_MIGRATION_AND_PRESERVATION=PASS");
 }
}''', encoding="utf-8")
    subprocess.run([str(java_home / "bin/javac.exe"), "-encoding", "UTF-8", "-source", "8", "-target", "8", "-d", str(folder), str(source), str(test)], check=True)
    subprocess.run([str(java_home / "bin/java.exe"), "-cp", str(folder), "DnsDefaultsTest"], check=True)
