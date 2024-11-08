#!/usr/bin/perl
use strict;
use warnings;
use threads;
use Thread::Queue;
use Carp qw(confess);

# 提取 TCP 握手失败的流 id

my $pcap_file = shift @ARGV;


# 检查是否提供了 PCAP 文件名
unless (defined $pcap_file) {
    die "Usage: $0 <pcap_file>\n 本脚本用于提取 TCP 握手失败的流 id";
}

print "Parsing PCAP file '$pcap_file'...\n";
# 读取 tshark 输出
my $tshark_output = `tshark -r '$pcap_file' -Y '(tcp.flags.syn == 1) or (tcp.seq == 1 and tcp.flags.ack == 1)' -T fields -e tcp.stream -e tcp.seq -e tcp.flags.ack -e tcp.flags.syn`;
if ($? != 0) {
    print "Error: tshark command failed\n";
    exit;
}
print "Parsing tshark output...\n";

my %streams;


# 处理 tshark 输出
foreach my $line (split /\n/, $tshark_output) {
    my ($streamid, $seq, $ack, $syn) = split /\t/, $line;

    # 只处理 TCP 流
    next unless defined $streamid;

    # 初始化流
    $streams{$streamid} //= { seqs => [], acks => [], syns => [] };

    push @{$streams{$streamid}{seqs}}, $seq;
    push @{$streams{$streamid}{acks}}, $ack;
    push @{$streams{$streamid}{syns}}, $syn;
}



# print size of streams
print "Number of streams: ", scalar keys %streams, "\n";

# 创建线程队列
my $queue = Thread::Queue->new();
my $result_queue = Thread::Queue->new();

# 将流添加到队列
foreach my $stream (keys %streams) {
    $queue->enqueue($stream);
}
$queue->end();


# 定义线程处理函数
sub process_stream {

    # my $thread_id = threads->tid();  # 获取当前线程的 ID
    # print "Thread $thread_id started\n";

    while (defined(my $stream = $queue->dequeue())) {
        my $seqs = $streams{$stream}{seqs};
        my $acks = $streams{$stream}{acks};
        my $syns = $streams{$stream}{syns};

        my $first_syn = 0;
        my $second_syn_ack = 0;
        my $last_ack = 0;

        for my $i (0 .. $#{$seqs}){
            my $seq = $seqs->[$i];
            my $ack = $acks->[$i];
            my $syn = $syns->[$i];

            confess "Expected \$seq to be numeric, but got '$seq'" unless $seq =~ /^\d+$/;
            confess "Expected \$ack to be 'True' or 'False', but got '$ack'" unless $ack =~ /^(True|False)$/;
            confess "Expected \$syn to be 'True' or 'False', but got '$syn'" unless $syn =~ /^(True|False)$/;
            
            if ($seq eq 0 && $ack eq "False" && $syn == "True") {
                # 如果是第一个握手包 
                $first_syn = 1;
            } else {if($seq eq 0 && $ack eq "True" && $syn == "False") {
                # 如果是第二个握手包
                $second_syn_ack = 1;
            } else {if($seq eq 1 && $ack eq "True" && $syn == "False") {
                # 如果是最后一个握手包
                $last_ack = 1;
            }}}
        }

        if ($first_syn == 1 && ($second_syn_ack == 0 || $last_ack == 0)) {
            $result_queue->enqueue($stream);
        }
    }
    # print "Thread $thread_id finished\n";
}

# 创建多个线程
my @threads;
for (1 .. 8) {  # 根据需要调整线程数量
    push @threads, threads->create(\&process_stream);
}

# 等待所有线程完成
$_->join() for @threads;
# 线程完成后，结束结果队列
$result_queue->end();

# 如果 result_queue 的长度为 0
if (defined $result_queue->pending() && $result_queue->pending() == 0) {
    print "No TCP Handshake error found\n";
    exit;
}

# 打印结果
print "TCP Streams Handshake error found, stream ids:\n";
while (defined(my $stream = $result_queue->dequeue())) {
    print "$stream\n";
}