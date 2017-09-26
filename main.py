from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import IParameter
from org.python.core.util import StringUtil
from java.io import PrintWriter

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("Burlap Length Modifier")
        callbacks.registerSessionHandlingAction(self)
        return

    def performAction(self, currentRequest, macroItems):
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = requestInfo.getHeaders()
        method = requestInfo.getMethod()
        msgBody = currentRequest.getRequest()[requestInfo.getBodyOffset():].tostring()
        burlapLen = hex(len(msgBody) - 4)[2:].zfill(8)
        resultBody = ''
        resultList = []
        burlapLen = [burlapLen[i:i+2] for i in range(0, len(burlapLen), 2)]

        for a in burlapLen:
            if a == "00":
                resultList.append(a)
            else:
                resultList.append(str(int(a,16)).zfill(2))
        for a in resultList:
            resultBody += str(chr(int(a)))

        resultBody += msgBody[4:]
        message = self._helpers.buildHttpMessage(headers, resultBody)

        currentRequest.setRequest(message)
        return
