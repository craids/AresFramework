using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;

namespace gui
{
    public partial class Form1 : Form
    {
        bool ff = false, rdf = false;
        public Form1()
        {
            InitializeComponent();
        }

       
        private void bn_choose_Click(object sender, EventArgs e)
        {

            OpenFileDialog dialog = new OpenFileDialog();
            dialog.InitialDirectory = "C:\\";
            dialog.Filter = "Executables (*.exe)|*.exe";
            DialogResult result = dialog.ShowDialog(this);
            tb_fileName.Text = dialog.FileName;
        }

        private void bn_submit_Click(object sender, EventArgs e)
        {
            string strCmdText = "";
            bool valid = true;
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            //if (ff)
            strCmdText = "/C AsmObf.exe " + tb_fileName.Text + " " + textBox1.Text + " \"" + textBox2.Text + "\"";
            /*else if (rdf)
                strCmdText = "/C C:\\FYPJ\\rdf.exe " + tb_fileName.Text + " " + textBox1.Text;
            else
                valid = false;*/
            if (valid)
            {
                startInfo.FileName = "cmd.exe";
                startInfo.Arguments = strCmdText;
                process.StartInfo = startInfo;
                process.Start();
                MessageBox.Show("Obfuscation Completed!");
                tb_fileName.Text = "";
                textBox1.Text = "";
                textBox2.Text = "";
            }
            else
                MessageBox.Show("One or more options are required");
        }

        private void button1_Click(object sender, EventArgs e)
        {
            SaveFileDialog dialog = new SaveFileDialog();
            dialog.InitialDirectory = "C:\\";
            dialog.Filter = "Executables (*.exe)|*.exe";
            DialogResult result = dialog.ShowDialog(this);
            textBox1.Text = dialog.FileName;
        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {

        }
    }
}

