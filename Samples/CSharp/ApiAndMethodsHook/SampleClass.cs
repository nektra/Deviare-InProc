using System;
using System.Collections.Generic;
using System.Windows.Forms;

namespace Test
{
    class SampleClass
    {
        public DialogResult Call(string text, string caption)
        {
            return MessageBox.Show(text, caption, MessageBoxButtons.OK);
        }

        public int val = 10;
    }
}
