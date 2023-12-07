<?php

function colored($text, $color)
{
    $color_codes = [
        'red' => "\033[31m",
        'green' => "\033[32m",
        'yellow' => "\033[33m",
        'blue' => "\033[34m",
        'magenta' => "\033[35m",
        'cyan' => "\033[36m"
    ];
    $end_code = "\033[0m";
    return $color_codes[$color] . $text . $end_code;
}

function categorize_gadgets($rp_linOutput, $patterns, $ignore_instructions, $limit)
{
    $gadgets_tree = [];

    // Collect all gadgets and sort them by the number of instructions
    $gadgets = [];
    $lines = explode("\n", $rp_linOutput);
    foreach ($lines as $line) {
        $line = trim(substr($line, 0, strrpos($line, '(')));
        if (strpos($line, '0x') === 0 && !preg_match('/' . implode('|', $ignore_instructions) . '/', $line)) {
            list($address, $instructions) = explode(': ', $line, 2);

            #strip Out high retn or if not divisable by 4
            if (preg_match('/retn\s*0x([a-fA-F0-9]+)/i', $instructions, $matches)) {
                $operandValue = hexdec($matches[1]);
            
                // Check if the operand is 65 or greater or not divisible by 4
                if ($operandValue >= 65 || $operandValue % 4 !== 0) {
                    continue;
                }
            }
            

            $gadgets[$address] = ['gadget' => $instructions, 'count' => substr_count($instructions, ';')];
        }
    }


    // Sort the gadgets by instruction count
    uasort($gadgets, function ($a, $b) {
        // Compare instruction count first
        if ($a['count'] !== $b['count']) {
            return $a['count'] <=> $b['count'];
        }

        // If instruction count is the same, prioritize "ret" over "retn"
        $retA = strpos($a['gadget'], '; ret ;') !== false;
        $retB = strpos($b['gadget'], '; ret ;') !== false;

        if ($retA && !$retB) {
            return -1;
        } elseif (!$retA && $retB) {
            return 1;
        }
        return 0;
    });


    // Process the sorted gadgets
    $searchStop = [];

    foreach ($gadgets as $address => $instructionData) {
        $instructions = $instructionData['gadget'];

        foreach ($patterns as $pattern) {

            #pattern is disabled
            if (isset($pattern['disabled'])) {
                continue;
            }

            if (!preg_match($pattern['pattern'], $instructions, $matches)) {
                continue;
            }

            $instructionMatch = $matches[0];
            $category = $pattern['category'];
            $subCategory = translateSubCategory($matches);

            // If subCategory has been processed, skip to the next pattern
            if (isset($searchStop[$subCategory])) {
                continue;
            }

            // Add "match" data to the gadget and organize in the gadgets tree
            $instructionData["match"] = $instructionMatch;
            $gadgets_tree[$category][$subCategory][$address] = $instructionData;

            // If a two-instruction gadget is found or the limit is reached, mark the subCategory as processed
            if ($instructionData["count"] == 2 || count($gadgets_tree[$category][$subCategory]) >= $limit) {
                $searchStop[$subCategory] = true;
            }

            break;
        }
    }


    return $gadgets_tree;
}

function translateSubCategory($matches)
{
    $reg1 = colored($matches[2], 'cyan');
    $reg2 = !empty($matches[4]) ? colored($matches[4], 'cyan') : (isset($matches[3]) ? colored($matches[3], 'cyan') : '');

    $operations = [
        'pop'  => "Load value to {$reg1}",
        'inc'  => "Increase {$reg1}",
        'lea'  => "Load Result of {$reg2} to {$reg1}",
        'add'  => "Add {$reg2} to {$reg1}",
        'sub'  => "Subtract {$reg2} from {$reg1}",
        'dec'  => "Decrease {$reg1}",
        "xor"  => "Make {$reg1} zero",
        "or"  => "BitWise OR {$reg2} on {$reg1} ",
        'mov'  => "Move {$reg2} to {$reg1}",
        'neg'  => "Negate {$reg1}",
        'xchg' => "Swap {$reg1} with {$reg2}",
        'push' => "Load {$reg1} to {$reg2}",
    ];

    return isset($operations[$matches[1]]) ? $operations[$matches[1]] : '';
}

function print_gadgets_tree($gadgets_tree)
{
    foreach ($gadgets_tree as $category => $subCategories) {
        echo $category . "\n";
        foreach ($subCategories as $subCategory => $gadgets) {
            echo "│   ├── " . colored($subCategory, 'red') . "\n";
            foreach ($gadgets as $address => $gadget) {

                #make our gadget colored based on the instruction found
                $gadget = str_replace($gadget['match'], colored($gadget['match'], 'yellow'), $gadget['gadget']);
                $address = colored($address, 'green');

                echo "│   │   ├── $address  # $gadget\n";
            }
        }
        echo "\n";
    }
}


$patterns = [
    ['pattern' => '/(mov)\s*(\[[a-zA-Z]{3}\]),\s*([a-zA-Z]{3})/', 'category' => 'DEREF'],
    ['pattern' => '/(mov)\s*([a-zA-Z]{3}),\s*(\[[a-zA-Z]{3}\])/', 'category' => 'DEREF'],
    ['pattern' => '/(mov)\s*([a-zA-Z]{3}),\s*(\[[a-zA-Z]{3}\+0x[0-9a-fA-F]+\])/', 'category' => 'DEREF'],
    ['pattern' => '/(mov)\s*(\[[a-zA-Z]{3}\+0x[0-9a-fA-F]+\]),\s*([a-zA-Z]{3})/', 'category' => 'DEREF'],
    ['pattern' => '/(lea)\s*([a-zA-Z]{3}),\s*(\[[a-zA-Z]{3}.0x[0-9a-fA-F]+\])/', 'category' => 'lea'],
    ['pattern' => '/(xor)\s*([a-zA-Z]{3}),\s*\2/', 'category' => 'ZEROING'],
    ['pattern' => '/\b(or)\s*([a-zA-Z]{3}),\s*([a-zA-Z]{3})/', 'category' => 'OR'],
    ['pattern' => '/(mov)\s*([a-zA-Z]{3}),\s*([a-zA-Z]{3})/', 'category' => 'MOV'],
    ['pattern' => '/\b(xchg)\s*([a-zA-Z]{3}),\s*([a-zA-Z]{3})/', 'category' => 'SWAP'],
    ['pattern' => '/\b(xchg)\s*(\[[a-zA-Z]{3}\]),\s*([a-zA-Z]{3})/', 'category' => 'SWAP DEREF'],
    ['pattern' => '/\b(xchg)\s*([a-zA-Z]{3}),\s*(\[[a-zA-Z]{3}\])/', 'category' => 'SWAP DEREF'],
    ['pattern' => '/\b(sub)\s*([a-zA-Z]{3}),\s*([a-zA-Z]{3})/', 'category' => 'SUB'],
    ['pattern' => '/\b(add)\s*([a-zA-Z]{3}),\s*([a-zA-Z]{3})/', 'category' => 'ADD'],
    ['pattern' => '/\b(pop)\s*([a-zA-Z]{3})/', 'category' => 'POP '],
    ['pattern' => '/\b(inc)\s*([a-zA-Z]{3})\b/', 'category' => 'INC'],
    ['pattern' => '/\b(dec)\s*([a-zA-Z]{3})\b/', 'category' => 'DEC'],
    ['pattern' => '/\b(neg)\s*([a-zA-Z]{3})\b/', 'category' => 'NEG'],
    ['pattern' => '/\b(push)\s*([a-zA-Z]{3}\b).*?(pop)\s*([a-zA-Z]{3}\b)/', 'category' => 'PUSH-POP']
];


$rp_lin_path = './rp-lin';

if (!file_exists($rp_lin_path)) {
    echo "rp-lin not found, downloading...\n";

    // Define the URL and the target ZIP file path
    $url = 'https://github.com/0vercl0k/rp/releases/download/v2.1.2/rp-lin-gcc.zip';

    // Download the ZIP file using curl
    shell_exec("curl -s -L $url --output - | zcat > $rp_lin_path");

    // Make the rp-lin file executable
    chmod($rp_lin_path, 0755);

    echo "rp-lin downloaded and ready to use.\n";
}


$options = getopt('', ['file:', 'bad-bytes::', 'max-size::', 'limit::']);

$bad_bytes = $options['bad-bytes'] ?? '';
$max_size = $options['max-size'] ?? 5;
$limit = $options['limit'] ?? 2;
$ignore_instructions = $options['ignore'] ?? ['jmp', 'call', ' byte '];

if (empty($options['file'])) {
    echo "Error: Missing --file option\n";
    exit(1);
}


$options['file'] = (array) ($options['file']);

$append = "";
$append .= $bad_bytes ? " --bad-bytes " . escapeshellarg($bad_bytes) : '';
$append .= $max_size ? " -r " . escapeshellarg($max_size) : '';

$output = "";
foreach ($options['file'] as $file) {
    if (!file_exists($file)) {
        echo "File $file does not exist\n";
        exit;
    }

    $ext = pathinfo($file, PATHINFO_EXTENSION);

    if ($ext != 'txt') {
        $command = $rp_lin_path . " --unique --file " . escapeshellarg($file) . $append;
        $output .= shell_exec($command); // execute command
    } else {
        $output .= file_get_contents($file);
    }
}

$gadgets_tree = categorize_gadgets($output, $patterns, $ignore_instructions, $limit);
print_gadgets_tree($gadgets_tree);
