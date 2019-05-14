namespace gui
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.lbl_msg = new System.Windows.Forms.Label();
            this.lb_msg = new System.Windows.Forms.Label();
            this.tb_fileName = new System.Windows.Forms.TextBox();
            this.bn_submit = new System.Windows.Forms.Button();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.bn_choose = new System.Windows.Forms.Button();
            this.button1 = new System.Windows.Forms.Button();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // lbl_msg
            // 
            this.lbl_msg.Location = new System.Drawing.Point(0, 0);
            this.lbl_msg.Name = "lbl_msg";
            this.lbl_msg.Size = new System.Drawing.Size(100, 23);
            this.lbl_msg.TabIndex = 7;
            // 
            // lb_msg
            // 
            this.lb_msg.AutoSize = true;
            this.lb_msg.Location = new System.Drawing.Point(217, 233);
            this.lb_msg.Name = "lb_msg";
            this.lb_msg.Size = new System.Drawing.Size(0, 13);
            this.lb_msg.TabIndex = 5;
            // 
            // tb_fileName
            // 
            this.tb_fileName.Location = new System.Drawing.Point(162, 30);
            this.tb_fileName.Name = "tb_fileName";
            this.tb_fileName.Size = new System.Drawing.Size(283, 20);
            this.tb_fileName.TabIndex = 9;
            // 
            // bn_submit
            // 
            this.bn_submit.Location = new System.Drawing.Point(174, 130);
            this.bn_submit.Name = "bn_submit";
            this.bn_submit.Size = new System.Drawing.Size(75, 23);
            this.bn_submit.TabIndex = 10;
            this.bn_submit.Text = "Obfuscate";
            this.bn_submit.UseVisualStyleBackColor = true;
            this.bn_submit.Click += new System.EventHandler(this.bn_submit_Click);
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // bn_choose
            // 
            this.bn_choose.Location = new System.Drawing.Point(33, 30);
            this.bn_choose.Name = "bn_choose";
            this.bn_choose.Size = new System.Drawing.Size(108, 23);
            this.bn_choose.TabIndex = 6;
            this.bn_choose.Text = "Choose a File";
            this.bn_choose.UseVisualStyleBackColor = true;
            this.bn_choose.Click += new System.EventHandler(this.bn_choose_Click);
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(33, 70);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(108, 23);
            this.button1.TabIndex = 11;
            this.button1.Text = "Choose Destination";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // textBox1
            // 
            this.textBox1.Location = new System.Drawing.Point(162, 70);
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new System.Drawing.Size(283, 20);
            this.textBox1.TabIndex = 12;
            this.textBox1.Text = " ";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(475, 189);
            this.Controls.Add(this.textBox1);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.bn_submit);
            this.Controls.Add(this.tb_fileName);
            this.Controls.Add(this.bn_choose);
            this.Controls.Add(this.lb_msg);
            this.Controls.Add(this.lbl_msg);
            this.Name = "Form1";
            this.Text = "Source Code Obfuscator";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lbl_msg;
        private System.Windows.Forms.Label lb_msg;
        private System.Windows.Forms.TextBox tb_fileName;
        private System.Windows.Forms.Button bn_submit;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Button bn_choose;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.TextBox textBox1;
    }
}

