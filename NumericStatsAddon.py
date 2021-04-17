from mitmproxy import ctx
import mitmproxy.http
import mitmproxy.addonmanager
from datetime import datetime

#Use: mitmproxy -r [dump_path] -s NumericStatsAddon.py --set filename=[output_file_name] threshold=[threshold_value]
#dump_name is the mitmproxy dump file path.
#output_file_name is the name give to output files. Optional. Default: Output
#threshold_value is the threshold value to perform a temporal analysis on a call. Optional. Default: 10
#After closing mitmproxy a file couple "filename.csv" and "filename.mf.csv" will be generated.

class Counter:
    def __init__(self):
        self.num = 0
        self.currentId = 1
        self.calls = []

    def getCallIndex(self, call):
        i = 0
        for x in self.calls:
            if x.call == call:
                return i
            i = i + 1
        else:
            return None

    def writeToFile(self):
        with open(ctx.options.filename + ".csv", 'w') as f:
            f.write("Id;Richiesta;Numero Occorrenze\n")
            for item in self.calls:
                f.write("%s\n" % item.__str__())

    def writeMostFrequentCalls(self, threshold):
        with open(ctx.options.filename+".mf.csv", 'w') as f:
            filtered_items = filter(lambda x: (x.number > threshold), self.calls)
            for item in filtered_items:
                f.write("%s\n\n" % item.frequency_mean__repr__())
                f.write("%s\n\n" % item.frequency_stats__repr__())
                f.write("%s\n" % item.frequency__repr__())

    def load(self, loader):
        loader.add_option(
            name = "filename",
            typespec = str,
            default = "Output.csv",
            help = "Name of output file",
        )
        loader.add_option(
            name = "threshold",
            typespec = int,
            default = 10,
            help = "Threshold value for most frequent",
        )

    def request(self, flow: mitmproxy.http.HTTPFlow):
        url = flow.request.url
        method = flow.request.method
        time = datetime.fromtimestamp(flow.request.timestamp_start)
        index = self.getCallIndex(url)
        if index == None:
            self.calls.append(CallEntry(self.currentId, url, method, time))
            self.currentId = self.currentId + 1
        else:
            self.calls[index].increment(time)

    def done(self):
        self.writeToFile()
        self.writeMostFrequentCalls(ctx.options.threshold)


class CallEntry:

    def __init__(self,callId,call,method,time):
        super().__init__()
        self.method = method
        self.id = callId
        self.call = call
        self.number = 1
        self.times = []
        self.times.append(time)

    def increment(self, time):
        self.number = self.number + 1
        self.times.append(time)

    def timeFrequencyMean(self):
        mean = 0
        times = sorted(self.times)
        timesLen = len(times)
        for i in range(0,timesLen):
            if i != (timesLen - 1):
                timeDiff = times[i+1] - times[i]
                mean = mean + timeDiff.seconds 
        return int(mean / (timesLen - 1)) 

    def timeFrequencyStats(self):
        statsCounter = {"0-1 minuto":0, "1-5 minuti":0, "5-15 minuti":0,"15-30 minuti":0, "30-45 minuti":0, "45-60 minuti":0, "60+ minuti":0}
        times = sorted(self.times)
        timesLen = len(times)
        for i in range(0,timesLen):
            if i != (timesLen - 1):
                timeDiff = (times[i+1] - times[i]).seconds
                statsCounter[self.getTimeFrequencyStasKey(timeDiff)] = statsCounter[self.getTimeFrequencyStasKey(timeDiff)] + 1
        return statsCounter
 
    def getTimeFrequencyStasKey(self, seconds):
        if seconds <= 60:
            return "0-1 minuto"
        if seconds > 60 and seconds <= 300:
            return "1-5 minuti"
        if seconds > 300 and seconds <= 900:
            return "5-15 minuti"
        if seconds > 900 and seconds <= 1800:
            return "15-30 minuti"
        if seconds > 1800 and seconds <= 2700:
            return "30-45 minuti"
        if seconds > 2700 and seconds <= 3600:
            return "45-60 minuti"
        if seconds > 3600:
            return "60+ minuti"

    def __str__(self):
        return f"{self.id};{self.method} {self.call};{self.number}"

    def __repr__(self):
        return self.__str__()

    def frequency__repr__(self):
        times = sorted(self.times)
        times_repr = "Id;Richiesta;Occorrenze\n"
        for time in times:
            times_repr = f"{times_repr}{self.id};{self.method} {self.call};{time}\n"
        return times_repr

    def frequency_stats__repr__(self):
        stats = self.timeFrequencyStats()
        frequency_stats_repr = "Tempo trascorso;Numero chiamate\n"
        for key, value in stats.items():
            frequency_stats_repr = f"{frequency_stats_repr}{key};{value}\n"
        return frequency_stats_repr

    def frequency_mean__repr__(self):
        return f"Richiesta;Tempo medio tra chiamate\n{self.method} {self.call};{self.timeFrequencyMean()}"

addons = [
    Counter()
]