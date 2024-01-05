// 182476535 and 3742084308
// sp+8  = 182476535
// sp+12 = 3742084308
// w0    = 182476535
// w1    = 182476535
func1:
    sub sp, sp, #16        // Allocate space for local variables
    str w0, [sp, 12]       // Store the value of w0 at [sp+12]
    str w1, [sp, 8]        // Store the value of w1 at [sp+8]
    ldr w1, [sp, 12]       // Load the value at [sp+12] into w1
    ldr w0, [sp, 8]        // Load the value at [sp+8] into w0
    cmp w1, w0             // Compare w1 and w0
    bls .L2                // Branch if less than or equal to .L2 (unsigned comparison)
    ldr w0, [sp, 12]       // Load the value at [sp+12] into w0
    b .L3                  // Branch to .L3
.L2:
    ldr w0, [sp, 8]        // Load the value at [sp+8] into w0
.L3:
    add sp, sp, 16         // Deallocate space for local variables
    ret                     // Return from the function
    .size func1, .-func1   // Define the size of the function
main:
    stp x29, x30, [sp, -48]!  // Store x29 and x30 on the stack, adjusting the stack pointer
    add x29, sp, 0            // Set up the frame pointer
    str x19, [sp, 16]         // Store the value of x19 at [sp+16]
    str w0, [x29, 44]         // Store the value of w0 at [x29+44]
    str x1, [x29, 32]         // Store the value of x1 at [x29+32]
    ldr x0, [x29, 32]         // Load the value at [x29+32] into x0
    add x0, x0, 8             // Add 8 to x0
    ldr x0, [x0]              // Load the value at the address in x0 into x0
    bl atoi                    // Call the atoi function (convert string to integer)
    mov w19, w0               // Move the result of atoi to w19
    ldr x0, [x29, 32]         // Load the value at [x29+32] into x0
    add x0, x0, 16            // Add 16 to x0
    ldr x0, [x0]              // Load the value at the address in x0 into x0
    bl atoi                    // Call the atoi function (convert string to integer)
    mov w1, w0                // Move the result of atoi to w1
    mov w0, w19               // Move the value of w19 to w0
    bl func1                  // Call the func1 function
    mov w1, w0                // Move the result of func1 to w1
    adrp x0, .LC0             // Load the address of .LC0 into x0 (address calculation)
    add x0, x0, :lo12:.LC0    // Add the lower 12 bits of .LC0 address to x0
    bl printf                 // Call printf function to print the formatted string
    mov w0, 0                 // Move 0 to w0 (return value)
    ldr x19, [sp, 16]         // Load the value at [sp+16] into x19
    ldp x29, x30, [sp], 48    // Restore x29, x30 and adjust the stack pointer
    ret                        // Return from the function
    .size main, .-main         // Define the size of the function

