Author: zlowram
Date: 12-30-2014 14:15
Title: 31c3ctf Web HTTP write-up
Template: post
Comments: enabled


In this web challenge they were giving us the full code of a [custom HTTP server](http://nopat.ch/g/web_http_src.tar.gz)
written in C and Ruby.

The implementation of the web server was interesting, as they had two different
modules that worked together by using [socat](http://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/). The main module was the one in
charge to process the HTTP request it got via stdin and serve the requested
file via stdout.

```c
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

void transmit(const char *buffer, size_t buf_size);
bool read_line(char *buffer, size_t *buf_size);
void log_request(const char *host, const char *path, const char *status);

int main(int argc, char **argv) {
    if (argc != 1) {
        fprintf(stderr, "usage: %s", argv[0]);
        exit(1);
    }

    const char *path= NULL;
    const char *host= NULL;
    size_t buf_size= 4096;
    char *buffer= calloc(buf_size, sizeof(*buffer));

    if (!read_line(buffer, &buf_size)) {
        goto invalid;
    }
    if (strncmp(buffer, "GET /", sizeof("GET /")-1) != 0) {
        goto invalid;
    }
    buffer+= sizeof("GET /")-1;
    buf_size-= sizeof("GET /")-1;
    path= buffer;
    char *space= strchr(buffer, ' ');
    if (space == NULL) {
        goto invalid;
    }
    buf_size-= space-buffer;
    buffer= space;
    *buffer= 0;
    buffer+= 1;
    buf_size-= 1;
    if ((strncmp(buffer, "HTTP/1.0\r\n", sizeof("HTTP/1.0\r\n")-1) != 0) &&
        (strncmp(buffer, "HTTP/1.1\r\n", sizeof("HTTP/1.1\r\n")-1) != 0)) {
        goto invalid;
    }
    buffer+= sizeof("HTTP/1.0\r\n")-1;
    buf_size-= sizeof("HTTP/1.0\r\n")-1;

    for (;;) {
        if (!read_line(buffer, &buf_size)) {
            goto invalid;
        }
        if (*buffer == '\r') {
            goto invalid;
        }
        if (strncmp(buffer, "Host: ", sizeof("Host: ")-1) == 0) {
            break;
        }
        char *eol= strchr(buffer, '\r');
        buf_size-= eol-buffer-2;
        buffer= eol+2;
    }
    buffer+= sizeof("Host: ")-1;
    buf_size-= sizeof("Host: ")-1;
    host= buffer;
    char *cr= strchr(buffer, '\r');
    *cr= 0;

    if (chdir("www-data") == -1) {
        perror("chdir");
        exit(2);
    }

    if (chdir(host) == -1) {
        goto _404;
    }

    int fd= open(path, O_RDONLY);
    if (fd == -1) {
        goto _404;
    }
    struct stat stat;
    if (fstat(fd, &stat) == -1) {
        goto _404;
    }
    const char *file= mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (file == NULL) {
        goto _404;
    }
    close(fd);

    log_request(host, path, "200");

    transmit("HTTP/1.0 200 OK\r\n\r\n", sizeof("HTTP/1.0 200 OK\r\n\r\n")-1);
    transmit(file, stat.st_size);
    munmap((void *)file, stat.st_size);

    exit(0);

invalid:
    log_request(host, path, "400");
    transmit("HTTP/1.0 400 Bad Request\r\n\r\n", sizeof("HTTP/1.0 400 Bad Request\r\n\r\n")-1);
    exit(0);
_404:
    log_request(host, path, "404");
    transmit("HTTP/1.0 404 Not Found\r\n\r\n", sizeof("HTTP/1.0 404 Not Found\r\n\r\n")-1);
    exit(0);
}


void transmit(const char *buffer, size_t buf_size) {
    size_t buf_pos= 0;
    while (buf_pos < buf_size) {
        int size= write(1, buffer+buf_pos, buf_size-buf_pos);
        if (size == -1) {
            perror("write");
            exit(2);
        }
        buf_pos+= size;
    }
}


bool read_line(char *buffer, size_t *buf_size) {
    char *eol= strchr(buffer, '\r');
    if (eol != NULL) {
        if (*(eol+1) != '\n') {
            return false;
        }
        return true;
    }

    char *buf_end= buffer+strlen(buffer);
    int size= read(0, buf_end, *buf_size-(buf_end-buffer)-1);
    if (size == -1) {
        perror("read");
        exit(2);
    }
    *buf_size+= size;
    buffer[*buf_size]= 0;
    
    eol= strchr(buffer, '\r');
    if (eol != NULL) {
        if (*(eol+1) != '\n') {
            return false;
        }
        return true;
    }
    return false;
}


void log_request(const char *host, const char *path, const char *status) {
    time_t time_t;
    time(&time_t);
    struct tm tm;
    localtime_r(&time_t, &tm);
    char time[32];
    strftime(time, sizeof(time), "%d/%b/%Y:%H:%M:%S %z", &tm);
    fprintf(stderr, "- - - [%s] \"GET http://%s/%s HTTP/1.0\" %s -\n", time, host, path, status);
}
```

The code itself is vulnerable to path traversal, but that was fixed with the
firewall plugins available. The firewall simple plugin just performed a simple
input validation of the path and the host header.

```ruby
class SimpleFirewall < Firewall

    def acceptable?(request)
        if request.path=~ /\A\/[A-Za-z0-9]+(\.[A-Za-z0-9]+)?\z/ and
           request["Host"]=~ /\A[A-Za-z0-9]+(\.[A-Za-z0-9]+)*(:[1-9][0-9]*)?\z/
            true
        else
            false
        end
    end

end

SimpleFirewall
```

When we payed attention to the code of both modules, we saw that the serve_file
module iterated over all the headers of the received HTTP request, looking for
the host header. What happens if the HTTP request have 2 host headers? Which
one would be the valid? In this case, the first host header, as one it found a
host header, it ignored all the other hedaers. Interesting, huh?

But wait, what about the firewall simple plugin? It validated the host header,
right? Paying attention to the fw.rb code (code snippet below), we observed
that it was iterating through all the HTTP request headers and storing them
in a hash. Aha! And now what happens if we have a duplicated header? Which one
would prevail? In this case would be the first that appear, because ruby
implements the hash in a way that if you define a duplicated key in the hash
declaration, only the last occurence would be valid.

```ruby
#!/usr/bin/ruby

class InputBuffer

    attr_reader :buffer

    def initialize(input)
        @input= input
        @buffer= ""
    end

    def read_nonblock(size)
        data= @input.read_nonblock(size)
        @buffer+= data
        data
    end

    def to_io
        @input
    end

end

class LineReader

    def initialize(input)
        @input= input
        @buffer= ""
        @eof= false
    end

    def read_line
        return if @eof
        until @buffer.include? "\r\n"
            begin
                @buffer+= @input.read_nonblock(4096)
            rescue ::Errno::EAGAIN
                IO.select([@input])
            rescue EOFError
                @eof= true
                return
            end
        end
        return if @buffer.start_with? "\r\n"
        line, @buffer= @buffer.split("\r\n", 2)
        line
    end

    def each
        while line= read_line
            yield line
        end
    end

    include Enumerable

end

class HTTPRequest

    attr_reader :path

    def initialize(line_reader)
        @path, @headers= parse(line_reader)
    end

    def [](name)
        @headers[name]
    end

    private

    def parse(line_reader)
        [parse_request_line(line_reader),
         parse_headers(line_reader)]
    end

    def parse_request_line(line_reader)
        request_line= line_reader.read_line
        return if request_line.nil?
        request_line=~ /\AGET (.*) HTTP\/1\.[01]\z/
        $1
    end

    def parse_headers(line_reader)
        line_reader.collect do |line|
            [$1, $2] if line=~ /\A([^:]*): *(.*)\z/
        end.compact.inject({}) { |h, x| h[x[0]]= x[1]; h }
    end

end

class Firewall

    def acceptable?(request)
        raise NotImplementedError
    end

    def test(request)
        abort unless acceptable?(request)
    end

    def abort
        STDOUT.write "HTTP/1.0 403 Forbidden\r\n\r\nForbidden"
        exit 0
    end

end

if ARGV.size < 2
    STDERR.puts "usage: <fw-plugin> <exec-args>"
    exit 1
end

plugin= eval(File.read("./fw-plugin/"+ARGV[0]+".rb")).new

buffer= InputBuffer.new(STDIN)
line_reader= LineReader.new(buffer)
request= HTTPRequest.new(line_reader)

plugin.test(request)

r, w= IO.pipe
if w.write_nonblock(buffer.buffer) != buffer.buffer.size
    STDOUT.write "HTTP/1.0 413 Request Entity Too Large\r\n\r\n413 Request Entity Too Large"
    exit 0
end
STDIN.reopen(r)
exec(*ARGV[1..-1])
```

It was then clear how to bypass the firewall. That is, duplicating the host
header, placing the malicious payload in the first header, and the valid
legitimate in the second, as the firewall would look at the second header while
the module in charge of serving files would use the first one.

Once we could exploit the path traversal vulnerability, which was the first
file we leaked? The /etc/passwd of course, and there was the flag!

The request that allowed to exploit the path traversal vulnerability and obtain
the flag is the following:

```markup
curl -v -H "Host: ../../../../../../../../../../../../etc" -H "Host: 90.31c3ctf.aachen.ccc.de" http://90.31c3ctf.aachen.ccc.de/passwd
```

![alt flag](http://nopat.ch/g/http_flag.png)


Greetings to my team, [Insanity](http://ka0labs.net)!
